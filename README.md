# Wifarm Agronomics API

A secure, role-based backend system for agricultural asset financing and micro-lending management. This API handles the complete lifecycle of agricultural loans, from client onboarding and guarantor verification to loan scheduling and payment tracking.

## 🚀 Features

- **Robust Auth**: JWT-based authentication with password hashing using `bcrypt`.
- **RBAC (Role-Based Access Control)**: Granular permissions for `admin`, `backoffice`, `midlevel`, and `subordinate` roles[cite: 1].
- **Client Onboarding**: Comprehensive KYC (Know Your Customer) capturing personal details, dual guarantors, Next of Kin, and local governance (LC1) verification[cite: 1].
- **Loan Management**:
    - Automated interest and monthly payment calculation[cite: 1].
    - Loan approval/rejection workflow[cite: 1].
    - Loan rescheduling (restructuring) capabilities[cite: 1].
- **Inventory Tracking**: Manage agricultural products and branch-specific stock[cite: 1].
- **Financial Audit**: Every significant system action is logged in an audit trail for compliance[cite: 1].
- **Database**: Optimized for TiDB/MySQL with connection pooling and context management[cite: 1].

## 🛠️ Tech Stack

- **Framework**: FastAPI (Python 3.11)[cite: 1].
- **Database**: TiDB / MySQL[cite: 1].
- **Security**: PyJWT, Bcrypt[cite: 1].
- **Dependency Management**: Metadata included for `uv` script runner[cite: 1].

## 📋 Environment Variables

The application utilizes a `tool.env-checker` to ensure all critical configurations are present before startup[cite: 1]. The following environment variables must be set in your cloud provider's dashboard:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Server port | `8000` |
| `LOGLEVEL` | Logging verbosity | `INFO` |
| `CODEWORDS_API_KEY` | Secret key for JWT signing[cite: 1] | (Required) |
| `TIDB_HOST` | Database host address[cite: 1] | (Required) |
| `TIDB_USER` | Database username[cite: 1] | (Required) |
| `TIDB_PASSWORD` | Database password[cite: 1] | (Required) |
| `TIDB_DATABASE` | Database name[cite: 1] | `wifarm` |

## 🛣️ API Endpoints

### Authentication
- `POST /auth/register` - Create a new subordinate account[cite: 1].
- `POST /auth/login` - Authenticate and receive a JWT[cite: 1].
- `GET /auth/me` - Get current user profile[cite: 1].

### Clients
- `GET /clients` - List clients (filtered by branch for subordinates)[cite: 1].
- `POST /clients` - Onboard a new client with guarantors and LC1 data[cite: 1].
- `GET /clients/{id}` - Detailed client profile[cite: 1].
- `PUT /clients/{id}` - Edit client details (Backoffice only)[cite: 1].

### Loans
- `GET /loans` - List all loans with status and search filters[cite: 1].
- `POST /loans` - Create a new loan application[cite: 1].
- `PUT /loans/{id}/approve` - Approve or reject pending loans[cite: 1].
- `POST /loans/{id}/payments` - Record a loan repayment[cite: 1].
- `PUT /loans/{id}/reschedule` - Reschedule loan period and payments[cite: 1].

### Inventory & Branches
- `GET /branches` - List all company branches[cite: 1].
- `GET /products` - List available agricultural products[cite: 1].
- `GET /inventory` - View stock levels across branches[cite: 1].

### System
- `GET /audit-logs` - View system audit trail (Admin/Backoffice)[cite: 1].

## 🧮 Loan Calculation Logic

The system uses a flat interest rate calculation[cite: 1]:
- **Principal**: Product Price × Quantity[cite: 1].
- **Interest**: Principal × (Rate / 100) × (Months / 12)[cite: 1].
- **Monthly Payment**: (Principal + Interest) / Months[cite: 1].

## 📦 Deployment Instructions

### Local Development
Run the script directly using `uv` or any Python 3.11 environment[cite: 1]:
```bash
python main.py
