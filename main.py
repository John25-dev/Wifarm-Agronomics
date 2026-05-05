# /// script
# requires-python = "==3.11.*"
# dependencies = [
#   "codewords-client==0.4.6",
#   "fastapi==0.116.1",
#   "pymysql==1.1.1",
#   "pyjwt==2.9.0",
#   "bcrypt==4.2.1"
# ]
# [tool.env-checker]
# env_vars = [
#   "PORT=8000",
#   "LOGLEVEL=INFO",
#   "CODEWORDS_API_KEY",
#   "CODEWORDS_RUNTIME_URI",
#   "TIDB_HOST",
#   "TIDB_PORT",
#   "TIDB_USER",
#   "TIDB_PASSWORD",
#   "TIDB_DATABASE"
# ]
# ///

from typing import Optional, Literal
from contextlib import contextmanager
from datetime import datetime, timedelta
import os, uuid, json

import pymysql
import pymysql.cursors
import jwt
import bcrypt

from codewords_client import logger, run_service
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

JWT_SECRET = os.environ.get("CODEWORDS_API_KEY", "wifarm-fallback-secret")
JWT_ALG = "HS256"

# ── Database ──

def _get_conn():
    return pymysql.connect(
        host=os.environ["TIDB_HOST"], port=int(os.environ.get("TIDB_PORT","4000")),
        user=os.environ["TIDB_USER"], password=os.environ["TIDB_PASSWORD"],
        database=os.environ.get("TIDB_DATABASE","wifarm"),
        ssl={"ca":None}, ssl_verify_cert=False,
        cursorclass=pymysql.cursors.DictCursor, autocommit=True)

@contextmanager
def db():
    c = _get_conn()
    try:
        cur = c.cursor()
        yield cur
    finally:
        cur.close(); c.close()

# ── Auth helpers ──

def _hash(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def _verify(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())
def _token(uid, role, email):
    return jwt.encode({"sub":uid,"role":role,"email":email,"exp":datetime.utcnow()+timedelta(hours=24)}, JWT_SECRET, algorithm=JWT_ALG)

async def auth_user(request: Request):
    h = request.headers.get("Authorization","")
    if not h.startswith("Bearer "): raise HTTPException(401,"Missing token")
    try: p = jwt.decode(h[7:], JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError: raise HTTPException(401,"Token expired")
    except: raise HTTPException(401,"Invalid token")
    with db() as cur:
        cur.execute("SELECT * FROM users WHERE id=%s AND status='active'",(p["sub"],))
        u = cur.fetchone()
    if not u: raise HTTPException(401,"User not found")
    return u

def role_guard(*roles):
    async def check(request: Request):
        u = await auth_user(request)
        if u["role"] not in roles: raise HTTPException(403,"Access denied")
        return u
    return check

def _audit(uid,action,etype,eid,reason=None,changes=None):
    with db() as cur:
        cur.execute("INSERT INTO audit_logs (id,user_id,action,entity_type,entity_id,reason,changes) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4())[:8],uid,action,etype,eid,reason,json.dumps(changes) if changes else None))

def _serial(v): return {k:(str(v) if isinstance(v,(datetime,)) else v) for k,v in (v or {}).items()}

# ── Models ──

class LoginReq(BaseModel):
    email:str = Field(..., description="Company email address")
    password:str = Field(..., description="Account password")
class RegReq(BaseModel):
    name:str; email:str; password:str=Field(...,min_length=6); phone:str; branch_id:str="br-001"
class ClientReq(BaseModel):
    name:str; national_id:str; phone:str; email:Optional[str]=None; address:str
    payment_method:Literal["mobile_money","bank"]="mobile_money"; payment_contact:str; down_payment:float=0; branch_id:str
    g1_name:str; g1_nid:str; g1_phone:str; g1_rel:str
    g2_name:str; g2_nid:str; g2_phone:str; g2_rel:str
    nok_name:str; nok_phone:str; nok_rel:str
    lc1_name:str; lc1_phone:str; lc1_nid:str
class EditReq(BaseModel):
    field:str; new_value:str; reason:str=Field(...,min_length=10)
class LoanReq(BaseModel):
    client_id:str; product_id:str; quantity:int=1; interest_rate:float=15; period_months:int
    number_plate:Optional[str]=None; engine_number:Optional[str]=None; chassis_number:Optional[str]=None; serial_code:Optional[str]=None
class ApproveReq(BaseModel):
    action:Literal["approve","reject"]; notes:str=""
class ReschedReq(BaseModel):
    new_period_months:int=Field(...,ge=1); reason:str=Field(...,min_length=10)
class PayReq(BaseModel):
    amount:float=Field(...,gt=0); payment_phone:str; payment_method:Literal["mobile_money","bank"]="mobile_money"

# ── App ──

app = FastAPI(title="Wifarm Agronomics API",description="Secure backend API for agricultural business management with JWT auth, role-based access, MySQL persistence",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"],allow_credentials=True)

class HealthRequest(BaseModel):
    ping: str = Field(default="health", description="Health check ping")

class HealthResponse(BaseModel):
    service: str = Field(..., description="Service name")
    status: str = Field(..., description="Service status")

@app.post("/", response_model=HealthResponse)
async def root(request: HealthRequest):
    return HealthResponse(service="Wifarm Agronomics API", status="running")

# ── Auth ──

@app.post("/auth/login")
async def login(r:LoginReq):
    with db() as cur:
        cur.execute("SELECT * FROM users WHERE email=%s AND status='active'",(r.email.lower().strip(),))
        u=cur.fetchone()
    if not u or not _verify(r.password,u["password_hash"]): raise HTTPException(401,"Invalid credentials")
    _audit(u["id"],"login","user",u["id"])
    return {"token":_token(u["id"],u["role"],u["email"]),"user":{k:str(v) for k,v in u.items() if k!="password_hash"}}

@app.post("/auth/register")
async def register(r:RegReq):
    with db() as cur:
        cur.execute("SELECT id FROM users WHERE email=%s",(r.email.lower().strip(),))
        if cur.fetchone(): raise HTTPException(400,"Email taken")
        uid=str(uuid.uuid4())[:8]
        cur.execute("INSERT INTO users(id,name,email,password_hash,role,branch_id,phone)VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (uid,r.name,r.email.lower().strip(),_hash(r.password),"subordinate",r.branch_id,r.phone))
    _audit(uid,"register","user",uid)
    return {"token":_token(uid,"subordinate",r.email),"user":{"id":uid,"name":r.name,"email":r.email,"role":"subordinate"}}

@app.get("/auth/me")
async def me(u=Depends(auth_user)): return {k:str(v) for k,v in u.items() if k!="password_hash"}

# ── Branches ──
@app.get("/branches")
async def branches(u=Depends(auth_user)):
    with db() as cur: cur.execute("SELECT * FROM branches ORDER BY name"); return cur.fetchall()

# ── Clients ──
@app.get("/clients")
async def clients(u=Depends(auth_user),search:str="",status:str="all"):
    with db() as cur:
        q,p="SELECT * FROM clients WHERE 1=1",[]
        if search: q+=" AND(name LIKE %s OR national_id LIKE %s OR phone LIKE %s)"; s=f"%{search}%"; p+=[s,s,s]
        if status!="all": q+=" AND status=%s"; p.append(status)
        if u["role"] not in("admin","backoffice"): q+=" AND branch_id=%s"; p.append(u["branch_id"])
        cur.execute(q+" ORDER BY created_at DESC LIMIT 200",p); return cur.fetchall()

@app.post("/clients")
async def add_client(r:ClientReq,u=Depends(auth_user)):
    cid=str(uuid.uuid4())[:8]
    with db() as cur:
        cur.execute("SELECT id FROM clients WHERE national_id=%s",(r.national_id,))
        if cur.fetchone(): raise HTTPException(400,"NID already exists")
        cur.execute("INSERT INTO clients(id,name,national_id,phone,email,address,payment_method,payment_contact,down_payment,branch_id,onboarded_by)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (cid,r.name,r.national_id,r.phone,r.email,r.address,r.payment_method,r.payment_contact,r.down_payment,r.branch_id,u["id"]))
        for g in[(r.g1_name,r.g1_nid,r.g1_phone,r.g1_rel),(r.g2_name,r.g2_nid,r.g2_phone,r.g2_rel)]:
            cur.execute("INSERT INTO guarantors(id,client_id,name,national_id,phone,relationship)VALUES(%s,%s,%s,%s,%s,%s)",(str(uuid.uuid4())[:8],cid,*g))
        cur.execute("INSERT INTO next_of_kin(id,client_id,name,phone,relationship)VALUES(%s,%s,%s,%s,%s)",(str(uuid.uuid4())[:8],cid,r.nok_name,r.nok_phone,r.nok_rel))
        cur.execute("INSERT INTO lc1_chairman(id,client_id,name,phone,national_id)VALUES(%s,%s,%s,%s,%s)",(str(uuid.uuid4())[:8],cid,r.lc1_name,r.lc1_phone,r.lc1_nid))
    _audit(u["id"],"onboard","client",cid)
    return {"id":cid,"message":"Client onboarded"}

@app.get("/clients/{cid}")
async def get_client(cid:str,u=Depends(auth_user)):
    with db() as cur:
        cur.execute("SELECT * FROM clients WHERE id=%s",(cid,)); c=cur.fetchone()
        if not c: raise HTTPException(404,"Not found")
        cur.execute("SELECT * FROM guarantors WHERE client_id=%s",(cid,)); c["guarantors"]=cur.fetchall()
        cur.execute("SELECT * FROM next_of_kin WHERE client_id=%s",(cid,)); c["next_of_kin"]=cur.fetchone()
        cur.execute("SELECT * FROM lc1_chairman WHERE client_id=%s",(cid,)); c["lc1_chairman"]=cur.fetchone()
    return c

@app.put("/clients/{cid}")
async def edit_client(cid:str,r:EditReq,u=Depends(role_guard("backoffice"))):
    ok=["name","phone","email","address","payment_method","payment_contact","status"]
    if r.field not in ok: raise HTTPException(400,f"Field not editable")
    with db() as cur:
        cur.execute(f"SELECT {r.field} FROM clients WHERE id=%s",(cid,)); old=cur.fetchone()
        if not old: raise HTTPException(404)
        cur.execute(f"UPDATE clients SET {r.field}=%s WHERE id=%s",(r.new_value,cid))
    _audit(u["id"],"edit","client",cid,r.reason,{r.field:{"old":str(old[r.field]),"new":r.new_value}})
    return {"ok":True}

# ── Products & Inventory ──
@app.get("/products")
async def products(u=Depends(auth_user),category:str=""):
    with db() as cur:
        if category: cur.execute("SELECT * FROM products WHERE category=%s ORDER BY name",(category,))
        else: cur.execute("SELECT * FROM products ORDER BY category,name")
        return cur.fetchall()

@app.get("/inventory")
async def inventory(u=Depends(auth_user),branch_id:str=""):
    with db() as cur:
        if branch_id: cur.execute("SELECT bi.*,p.name pname,p.category,p.price FROM branch_inventory bi JOIN products p ON p.id=bi.product_id WHERE bi.branch_id=%s",(branch_id,))
        else: cur.execute("SELECT bi.*,p.name pname,p.category,p.price,b.name bname FROM branch_inventory bi JOIN products p ON p.id=bi.product_id JOIN branches b ON b.id=bi.branch_id")
        return cur.fetchall()

# ── Loans ──
@app.post("/loans")
async def add_loan(r:LoanReq,u=Depends(role_guard("admin","midlevel","backoffice"))):
    with db() as cur:
        cur.execute("SELECT * FROM products WHERE id=%s",(r.product_id,)); p=cur.fetchone()
        if not p: raise HTTPException(404,"Product not found")
        prin=float(p["price"])*r.quantity; intr=prin*(r.interest_rate/100)*(r.period_months/12)
        tot=prin+intr; mo=tot/r.period_months
        lid=str(uuid.uuid4())[:8]; lnid=f"WF-LN-{datetime.now().strftime('%y%m%d')}{lid[:2].upper()}"
        mat=(datetime.now()+timedelta(days=r.period_months*30)).strftime("%Y-%m-%d")
        acode=f"WF-AST-{r.product_id.replace('p-','')}{lid[:5].upper()}"
        cur.execute("INSERT INTO loans(id,loan_id,client_id,principal,interest_rate,period_months,interest_amount,total_amount,monthly_payment,maturity_date,balance)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (lid,lnid,r.client_id,prin,r.interest_rate,r.period_months,round(intr,2),round(tot,2),round(mo,2),mat,round(tot,2)))
        cur.execute("INSERT INTO loan_assets(id,loan_id,product_id,product_name,asset_code,quantity,unit_price,number_plate,engine_number,chassis_number,serial_code)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4())[:8],lid,r.product_id,p["name"],acode,r.quantity,p["price"],r.number_plate,r.engine_number,r.chassis_number,r.serial_code))
    _audit(u["id"],"create_loan","loan",lid)
    return {"id":lid,"loan_id":lnid,"asset_code":acode,"total":round(tot,2),"monthly":round(mo,2)}

@app.get("/loans")
async def loans(u=Depends(auth_user),status:str="",search:str=""):
    with db() as cur:
        q="SELECT l.*,c.name cname,c.phone cphone FROM loans l JOIN clients c ON c.id=l.client_id WHERE 1=1"; p=[]
        if status: q+=" AND l.status=%s"; p.append(status)
        if search: q+=" AND(l.loan_id LIKE %s OR c.name LIKE %s OR c.phone LIKE %s)"; s=f"%{search}%"; p+=[s,s,s]
        cur.execute(q+" ORDER BY l.created_at DESC",p); ls=cur.fetchall()
        for l in ls: cur.execute("SELECT * FROM loan_assets WHERE loan_id=%s",(l["id"],)); l["assets"]=cur.fetchall()
        return ls

@app.put("/loans/{lid}/approve")
async def approve(lid:str,r:ApproveReq,u=Depends(role_guard("admin","backoffice"))):
    with db() as cur:
        cur.execute("SELECT * FROM loans WHERE id=%s AND status='pending'",(lid,)); l=cur.fetchone()
        if not l: raise HTTPException(404)
        ns="active" if r.action=="approve" else "rejected"
        np=(datetime.now()+timedelta(days=30)).strftime("%Y-%m-%d") if r.action=="approve" else None
        cur.execute("UPDATE loans SET status=%s,authorized_by=%s,authorization_notes=%s,next_payment_date=%s WHERE id=%s",(ns,u["id"],r.notes,np,lid))
    _audit(u["id"],f"loan_{r.action}","loan",lid,r.notes)
    return {"status":ns}

@app.put("/loans/{lid}/reschedule")
async def resched(lid:str,r:ReschedReq,u=Depends(role_guard("admin","backoffice"))):
    with db() as cur:
        cur.execute("SELECT * FROM loans WHERE id=%s AND status IN('active','rescheduled')",(lid,)); l=cur.fetchone()
        if not l: raise HTTPException(404)
        nm=float(l["balance"])/r.new_period_months; nmat=(datetime.now()+timedelta(days=r.new_period_months*30)).strftime("%Y-%m-%d")
        cur.execute("INSERT INTO loan_reschedules(id,loan_id,old_period_months,new_period_months,old_monthly_payment,new_monthly_payment,old_maturity_date,new_maturity_date,reason,approved_by)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4())[:8],lid,l["period_months"],r.new_period_months,l["monthly_payment"],round(nm,2),l["maturity_date"],nmat,r.reason,u["id"]))
        cur.execute("UPDATE loans SET period_months=%s,monthly_payment=%s,maturity_date=%s,status='rescheduled' WHERE id=%s",(r.new_period_months,round(nm,2),nmat,lid))
    _audit(u["id"],"reschedule","loan",lid,r.reason)
    return {"monthly":round(nm,2),"maturity":nmat}

@app.post("/loans/{lid}/payments")
async def pay(lid:str,r:PayReq,u=Depends(auth_user)):
    with db() as cur:
        cur.execute("SELECT * FROM loans WHERE id=%s AND status IN('active','rescheduled')",(lid,)); l=cur.fetchone()
        if not l: raise HTTPException(404)
        if r.amount>float(l["balance"]): raise HTTPException(400,"Exceeds balance")
        nb=float(l["balance"])-r.amount; txn=f"TXN-{r.payment_method[:2].upper()}-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:4]}"
        cur.execute("INSERT INTO loan_payments(id,loan_id,amount,transaction_id,payment_method,payment_phone,balance_after)VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4())[:8],lid,r.amount,txn,r.payment_method,r.payment_phone,round(nb,2)))
        ns="paid" if nb<=0 else l["status"]; npd=(datetime.now()+timedelta(days=30)).strftime("%Y-%m-%d") if nb>0 else None
        cur.execute("UPDATE loans SET balance=%s,status=%s,next_payment_date=%s WHERE id=%s",(round(nb,2),ns,npd,lid))
    _audit(u["id"],"payment","loan",lid)
    return {"txn_id":txn,"amount":r.amount,"balance":round(nb,2),"status":ns}

# ── Audit ──
@app.get("/audit-logs")
async def audits(u=Depends(role_guard("admin","backoffice")),limit:int=50):
    with db() as cur:
        cur.execute("SELECT a.*,u.name uname FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT %s",(limit,))
        return cur.fetchall()

@app.get("/")
async def root():
    return {"service": "Wifarm Agronomics API", "status": "running"}
