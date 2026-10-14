# API Design

> **v3 status note:** design reference. The current implementation exposes the same routes, but scanning is performed exclusively by the custom Python engine (`scanner_type` is always `custom`; external scanners such as Nmap/Nikto/SQLMap are **not** used). See `README.md` and `docs/technical-assessment.md`.

## Base URL
```
http://localhost:5000/api/v1
```

## Authentication
All protected endpoints require:
```
Authorization: Bearer <jwt_token>
```

## Response Format
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation successful",
  "pagination": { "page": 1, "limit": 20, "total": 100 }
}
```

## Error Response
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid email format",
    "details": [...]
  }
}
```

---

## 1. Authentication Endpoints

### POST /auth/register
Create a new user account.
```json
// Request
{ "firstName": "John", "lastName": "Doe", "email": "john@example.com", "password": "SecureP@ss123" }

// Response 201
{ "success": true, "data": { "id": "uuid", "email": "john@example.com", "role": "viewer" }, "message": "Registration successful" }
```

### POST /auth/login
```json
// Request
{ "email": "john@example.com", "password": "SecureP@ss123" }

// Response 200
{ "success": true, "data": { "token": "jwt_token_here", "user": { "id": "uuid", "email": "john@example.com", "role": "analyst", "firstName": "John" } } }
```

### GET /auth/me
Get current user profile. **Auth required.**
```json
// Response 200
{ "success": true, "data": { "id": "uuid", "firstName": "John", "lastName": "Doe", "email": "john@example.com", "role": "analyst", "mfaEnabled": false, "createdAt": "2026-01-15T10:30:00Z" } }
```

### PUT /auth/profile
Update profile. **Auth required.**
```json
// Request
{ "firstName": "John", "lastName": "Smith" }
```

### PUT /auth/password
Change password. **Auth required.**
```json
// Request
{ "currentPassword": "OldP@ss123", "newPassword": "NewP@ss456" }
```

### POST /auth/verify-email
Verify email ownership using the token from the verification email.
```json
// Request
{ "token": "96-char-hex-token" }
// Response 200
{ "success": true, "message": "Email verified successfully! You can now log in." }
```

### POST /auth/resend-verification
Resend the verification email. **Rate limited (5/hour).**
```json
// Request
{ "email": "john@example.com" }
```

### POST /auth/forgot-password
Send a password reset link. Always returns the same message (prevents user enumeration). **Rate limited (5/hour).**
```json
// Request
{ "email": "john@example.com" }
```

### POST /auth/reset-password
Set a new password with the token from the reset email.
```json
// Request
{ "token": "96-char-hex-token", "newPassword": "NewP@ss456" }
// Response 200
{ "success": true, "message": "Password reset successfully. You can now log in." }
```

### POST /auth/mfa/setup
Generate a TOTP secret + provisioning URI. **Auth required.** MFA stays disabled until the first code is verified.
```json
// Response 200
{ "success": true, "data": { "secret": "BASE32SECRET", "otpauthUrl": "otpauth://totp/..." } }
```

### POST /auth/mfa/enable
Activate MFA after verifying the first TOTP code. **Auth required.**
```json
// Request
{ "code": "123456" }
```

### POST /auth/mfa/disable
Disable MFA after verifying the current TOTP code. **Auth required.**
```json
// Request
{ "code": "123456" }
```

### POST /auth/mfa/verify
Complete MFA login — exchange the short-lived mfa token + TOTP code for a full JWT.
```json
// Request
{ "mfaToken": "jwt", "code": "123456" }
// Response 200
{ "success": true, "data": { "token": "jwt_token_here", "user": { ... } } }
```

### Login with MFA
When an account has MFA enabled, `POST /auth/login` returns a short-lived `mfaToken` instead of a JWT:
```json
// Response 200
{ "success": true, "data": { "mfaRequired": true, "mfaToken": "jwt" } }
```
The client then completes the flow via `POST /auth/mfa/verify`.

---

## 2. Asset Endpoints

### GET /assets
List user's assets. **Role: analyst+**
```
Query params: ?page=1&limit=20&type=ip&search=192.168
```
```json
// Response 200
{ "success": true, "data": [ { "id": "uuid", "name": "Web Server", "type": "ip", "target": "192.168.1.100", "description": "Production web server", "isActive": true, "createdAt": "2026-01-15T10:30:00Z" } ], "pagination": { "page": 1, "limit": 20, "total": 5 } }
```

### POST /assets
Create new asset. **Role: analyst+**
```json
// Request
{ "name": "Web Server", "type": "ip", "target": "192.168.1.100", "description": "Production web server" }

// Response 201
{ "success": true, "data": { "id": "uuid", ... }, "message": "Asset created" }
```

### GET /assets/:id
Get single asset. **Role: analyst+**

### PUT /assets/:id
Update asset. **Role: analyst+**

### DELETE /assets/:id
Delete asset. **Role: analyst+**

---

## 3. Scan Endpoints

### GET /scans
List user's scans. **Role: viewer+**
```
Query params: ?page=1&limit=20&status=completed&scannerType=nmap
```

### POST /scans
Launch new scan. **Role: analyst+**
```json
// Request
{ "assetId": "uuid", "scannerType": "nmap", "parameters": { "ports": "1-1000", "intensity": "normal" }, "policyId": "uuid" }

// Response 201
{ "success": true, "data": { "id": "uuid", "status": "queued", "scannerType": "nmap", "createdAt": "2026-01-15T10:30:00Z" }, "message": "Scan queued" }
```

### GET /scans/:id
Get scan details with vulnerability summary. **Role: viewer+**
```json
// Response 200
{ "success": true, "data": { "id": "uuid", "status": "completed", "scannerType": "nmap", "asset": { "id": "uuid", "name": "Web Server", "target": "192.168.1.100" }, "startedAt": "2026-01-15T10:31:00Z", "completedAt": "2026-01-15T10:35:00Z", "totalVulnerabilities": 12, "severitySummary": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 1 } } }
```

### POST /scans/:id/cancel
Cancel running scan. **Role: analyst+**

### POST /scans/:id/retry
Retry failed scan. **Role: analyst+**

### GET /scans/:id/vulnerabilities
List vulnerabilities for a scan. **Role: viewer+**
```
Query params: ?severity=critical&page=1&limit=50
```
```json
// Response 200
{ "success": true, "data": [ { "id": "uuid", "title": "SSH OpenSSH 7.6p1 - Username Enumeration", "severity": "medium", "cvssScore": 5.3, "cveId": "CVE-2018-15473", "affectedComponent": "22/tcp ssh", "description": "OpenSSH is vulnerable to username enumeration...", "remediation": "Upgrade OpenSSH to version 7.8 or later" } ] }
```

---

## 4. Scan Policy Endpoints

### GET /policies
List scan policies. **Role: analyst+**

### POST /policies
Create scan policy. **Role: admin**
```json
// Request
{ "name": "Quick Nmap Scan", "scannerType": "nmap", "configuration": { "ports": "1-1000", "timing": "T3", "scripts": ["default"] }, "description": "Fast scan of common ports" }
```

### PUT /policies/:id
Update policy. **Role: admin**

### DELETE /policies/:id
Delete policy. **Role: admin**

---

## 5. Report Endpoints

### POST /reports
Generate report. **Role: viewer+**
```json
// Request
{ "scanId": "uuid", "title": "Security Assessment Report", "format": "pdf" }

// Response 202
{ "success": true, "data": { "id": "uuid", "status": "generating" }, "message": "Report generation started" }
```

### GET /reports
List user's reports. **Role: viewer+**

### GET /reports/:id
Get report metadata. **Role: viewer+**

### GET /reports/:id/download
Download report file. **Role: viewer+**

---

## 6. Dashboard Endpoints

### GET /dashboard/stats
User dashboard statistics. **Role: viewer+**
```json
// Response 200
{ "success": true, "data": { "totalAssets": 15, "totalScans": 42, "totalVulnerabilities": 156, "severityDistribution": { "critical": 5, "high": 23, "medium": 67, "low": 45, "info": 16 }, "recentScans": [...], "scanTrend": [ { "date": "2026-01-10", "count": 3 }, { "date": "2026-01-11", "count": 5 } ] } }
```

### GET /dashboard/admin
Admin system statistics. **Role: admin**
```json
// Response 200
{ "success": true, "data": { "totalUsers": 25, "activeScans": 3, "systemHealth": { "database": "connected", "redis": "connected", "workers": 2 } } }
```

---

## 7. Admin Endpoints

### GET /admin/users
List all users. **Role: admin**

### PUT /admin/users/:id
Update user role/status. **Role: admin**
```json
// Request
{ "role": "analyst", "isActive": true }
```

### GET /admin/audit-logs
View audit trail. **Role: admin**
```
Query params: ?userId=uuid&action=scan.create&from=2026-01-01&to=2026-01-31
```

---

## 8. Notification Endpoints

### POST /notifications/test-email
Send test email. **Role: admin**

### POST /notifications/test-webhook
Test webhook URL. **Role: admin**

---

## 9. Health Check

### GET /health
```json
// Response 200 (no auth required)
{ "status": "ok", "timestamp": "2026-01-15T10:30:00Z", "version": "1.0.0" }
```

---

## HTTP Status Codes Used

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (async processing) |
| 400 | Bad Request / Validation Error |
| 401 | Unauthorized |
| 403 | Forbidden (insufficient role) |
| 404 | Not Found |
| 409 | Conflict (duplicate email) |
| 429 | Too Many Requests |
| 500 | Internal Server Error |
