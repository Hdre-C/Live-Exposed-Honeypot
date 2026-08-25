# Phase 2 — Install & Populate MySQL

In this phase, MySQL was installed on the honeypot VM, populated with dummy corporate data, and configured to log database activity for later analysis.

---

## 1. Install MySQL Requirements

Before installing MySQL, I installed the required:

- **Microsoft Visual C++ 2019 Redistributable Package (x64)**

This package is required for MySQL to run correctly on Windows.

---

## 2. Install MySQL

MySQL was installed using the **Developer Default / Full** installation option so that MySQL Workbench and the graphical management tools were included.

During setup:

- Default installation settings were used
- A **strong root password** was configured
- MySQL Workbench was installed
- The MySQL service was configured

After installation, I opened **MySQL Workbench**, created a new connection, and successfully connected to the local MySQL Server.

> 📸 **IMAGE 1 — MySQL Workbench Connection**
>
> Take a screenshot showing MySQL Workbench successfully connected to the server.

```html
<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL Workbench Connection">
</p>
```

---

## 3. Populate the Database

The provided `db_info_import.sql` script was imported into MySQL Workbench to create a realistic dummy corporate database.

The import created the schema:

```text
lnp_corp
```

After execution, I refreshed the **Schemas** tab to confirm that the database and tables were successfully created.

> ⚠️ The import may appear frozen while processing the dummy data. If the import fails, retry the script or reduce the number of generated users.

> 📸 **IMAGE 2 — lnp_corp Schema**
>
> Take a screenshot showing the `lnp_corp` schema and its tables inside MySQL Workbench.

```html
<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="lnp_corp Database Schema">
</p>
```

---

## 4. Enable MySQL General Logging

MySQL general logging was enabled to record database connections and queries.

The following commands were executed:

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'FILE';
SHOW VARIABLES LIKE 'general_log%';
```

This allows MySQL activity to be written to a local log file for later collection and analysis.

> 📸 **IMAGE 3 — General Logging Enabled**
>
> Take a screenshot of the query results showing that `general_log` is enabled.

```html
<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL General Logging Enabled">
</p>
```

---

## 5. Configure the MySQL Log File

The MySQL configuration file was replaced at:

```text
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
```

The configuration enables network access and writes MySQL activity to:

```text
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

After updating `my.ini`, the **MySQL80** service was restarted using:

```text
services.msc
```

---

## 6. Verify Logging

A few test `SELECT` queries were executed inside MySQL Workbench.

Example:

```sql
USE lnp_corp;

SELECT * 
FROM users
LIMIT 10;
```

The `mysql_general.log` file was then checked to confirm that the queries were being recorded.

> 📸 **IMAGE 4 — MySQL Log Verification**
>
> Take a screenshot of `mysql_general.log` showing the test SQL queries being logged.

```html
<p align="center">
  <img src="YOUR_IMGUR_LINK" width="1200" alt="MySQL General Log Verification">
</p>
```

---

## Phase 2 Complete

At the end of Phase 2:

- MySQL Server is installed
- MySQL Workbench is connected
- The `lnp_corp` dummy database is populated
- General query logging is enabled
- MySQL activity is written to `mysql_general.log`

The log path will be used in **Phase 3** when configuring the Data Collection Rule (DCR).
