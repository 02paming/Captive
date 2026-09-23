-- 1. 데이터베이스 생성 및 선택
CREATE DATABASE IF NOT EXISTS internal_db;
USE internal_db;

-- 2. users 테이블 생성 (유저 정보)
CREATE TABLE users (
    user_id VARCHAR(50) NOT NULL PRIMARY KEY,
    user_password VARCHAR(255) NOT NULL
);

-- 3. employees 테이블 생성 (사원 정보)
CREATE TABLE employees (
    employee_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL UNIQUE,
    CONSTRAINT fk_emp_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- 4. online_ip 테이블 생성 (접속 중인 PC IP)
CREATE TABLE online_ip (
    employee_id INT NOT NULL,
    online_ip CHAR(15) NOT NULL,
    CONSTRAINT fk_online_emp FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

-- 5. no_access_ip 테이블 생성 (불법 사이트 IP 목록)
CREATE TABLE no_access_ip (
    no_access_ip CHAR(15) NOT NULL PRIMARY KEY,
    no_access_domain VARCHAR(255) NOT NULL
);

-- 6. no_access_addr_log 테이블 생성 (불법 사이트 접근 로그)
CREATE TABLE no_access_addr_log (
    employee_id INT NOT NULL,
    no_access_ip CHAR(15) NOT NULL,
    access_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_emp FOREIGN KEY (employee_id) REFERENCES employees(employee_id),
    CONSTRAINT fk_log_ip FOREIGN KEY (no_access_ip) REFERENCES no_access_ip(no_access_ip)
);