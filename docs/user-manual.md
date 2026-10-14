# User Manual

> **v3 status note:** updated flows — the app runs one scanner (the custom Python engine, shown as “VulnScan Pro”). Steps below that mention selecting Nmap/Nikto/OpenVAS/WPScan/SQLMap no longer apply.

## 1. Getting Started

### System Requirements
- Modern web browser (Chrome, Firefox, Edge)
- Network access to the VulnScan Pro server

### First-Time Setup
1. Navigate to `http://localhost:3000` in your browser
2. Click **Register** to create an account
3. Fill in your name, email, and password
4. Log in with your credentials

### Logging In
1. Enter your registered email and password
2. Click **Sign In**
3. You'll be redirected to the Dashboard

## 2. Dashboard

The dashboard provides an at-a-glance view of your security posture:

- **Stats Cards**: Total assets, scans, vulnerabilities, and critical issues
- **Severity Chart**: Doughnut chart showing vulnerability distribution by severity
- **Scan Trend**: Line chart showing scanning activity over the past 30 days
- **Recent Scans**: Table of your latest scan activities

## 3. Managing Assets

### Adding a Target
1. Navigate to **Assets** from the sidebar
2. Click **Add Asset**
3. Fill in:
   - **Name**: Descriptive label (e.g., "Production Web Server")
   - **Type**: IP Address, Domain, or Subnet
   - **Target**: The actual IP/domain/CIDR (e.g., `192.168.1.100`)
   - **Description**: Optional notes
4. Click **Save**

### Editing/Deleting Assets
- Click the **Edit** icon in the Actions column to modify
- Click the **Delete** icon to remove (confirmation required)

## 4. Running Scans

### Launching a New Scan
1. Navigate to **Scans** from the sidebar
2. Click **New Scan**
3. Select:
   - **Target**: Choose from your assets
   - **Scanner**: Nmap, Nikto, OpenVAS, WPScan, SQLMap, or Custom
   - **Parameters**: Configure scan options (varies by scanner)
4. Click **Start Scan**
5. The scan enters the queue and begins processing

### Scan Statuses
| Status | Meaning |
|--------|---------|
| Queued | Waiting to be processed |
| Running | Currently executing |
| Completed | Finished successfully |
| Failed | Error occurred |
| Cancelled | Manually stopped |

### Viewing Results
1. Click on a scan row to open the **Scan Detail** page
2. View the severity summary and vulnerability list
3. Click any vulnerability to expand details

## 5. Generating Reports

1. From a scan detail page, click **Generate Report**
2. Choose format: **PDF** or **HTML**
3. Enter a report title
4. Click **Generate**
5. Once ready, download from the **Reports** page

## 6. User Roles

| Role | Permissions |
|------|------------|
| **Viewer** | View dashboards, scan results, download reports |
| **Analyst** | All Viewer permissions + create assets, run scans |
| **Admin** | All permissions + manage users, view audit logs |

## 7. Admin Panel (Admin Only)

### Managing Users
- View all registered users
- Change user roles (Viewer, Analyst, Admin)
- Activate/deactivate accounts

### Audit Logs
- View a chronological log of all system actions
- Filter by user, action type, or date range

## 8. Troubleshooting

| Issue | Solution |
|-------|----------|
| Can't log in | Check email/password, ensure account is active |
| Scan stuck in "Queued" | Verify the worker service is running |
| Scan failed | Check error message, ensure scanner tool is installed |
| Report generation failed | Check disk space and scan has vulnerabilities |
| Slow dashboard | Clear browser cache, check network connection |
