# VaultLock Java Stack Setup Guide

## 🚀 Native Compilation & Execution

### 1. Download SQLite Driver
Ensure you download the SQLite JDBC driver jar dependency (e.g., `sqlite-jdbc-3.x.x.jar`) and keep it in your root compilation working directory path.

### 2. Compile Server Code
```bash
javac App.java


### 3. Run Application Server Node
Bash
# Windows
java -cp ".;sqlite-jdbc-3.x.x.jar" App

# Linux / Mac OS
java -cp ".:sqlite-jdbc-3.x.x.jar" App