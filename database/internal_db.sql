USE internal_db;

-- 테이블 구축

-- 1. 가입 요청자 테이블
CREATE TABLE `prospective_members` (
    `member_id` VARCHAR(50) NOT NULL UNIQUE COMMENT '가입 요청 아이디',
    `password` VARCHAR(255) NOT NULL COMMENT '가입 요청 비밀번호',
    `date_of_request` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '가입 요청 일자(한달 후 자동 삭제)',
    `email` VARCHAR(255) NOT NULL UNIQUE COMMENT '이메일',
    `address` VARCHAR(255) NOT NULL COMMENT '실제 주소',
    `phone_number` CHAR(11) NOT NULL UNIQUE COMMENT '휴대 전화 번호',
    `jumin_no` CHAR(13) NOT NULL UNIQUE COMMENT '주민 번호',
    PRIMARY KEY (`member_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. 사원 테이블
CREATE TABLE `employees` (
    `employee_number` INT NOT NULL AUTO_INCREMENT UNIQUE COMMENT '사원번호',
    `employee_id` VARCHAR(50) NOT NULL UNIQUE COMMENT '사원 아이디, prospective_members 테이블의 member_id 복사',
    `hire_date` DATE NOT NULL COMMENT '입사일',
    `deleted_at` DATE DEFAULT NULL COMMENT '사원 임시 삭제 일자(5년 보관 후 자동 삭제)',
    `email` VARCHAR(255) NOT NULL UNIQUE COMMENT '사원 이메일, prospective_members 테이블의 email 복사',
    `address` VARCHAR(255) NOT NULL COMMENT '사원 실제 주소, prospective_members 테이블의 address 복사',
    `phone_number` CHAR(11) NOT NULL UNIQUE COMMENT '사원 휴대 전화 번호, prospective_members 테이블의 phone_number 복사',
    `jumin_no` CHAR(13) NOT NULL UNIQUE COMMENT '사원 주민 번호, prospective_members 테이블의 jumin_no 복사',
    `is_manager` BOOLEAN NOT NULL DEFAULT 0 COMMENT '관리자 아이디 여부',
    PRIMARY KEY (`employee_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. 접근 금지 사이트 테이블
CREATE TABLE `no_access_addr` (
    `no_access_domain` VARCHAR(255) NOT NULL COMMENT '접근 금지 사이트 도메인',
    `deleted_at` DATE DEFAULT NULL COMMENT '접근 금지 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`no_access_domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. 접근 금지 사이트 접근 로그 테이블
CREATE TABLE `no_access_addr_log` (
    `employee_id` INT NOT NULL COMMENT '사원번호, employees 테이블의 employee_id 참조',
    `no_access_domain` VARCHAR(255) NOT NULL COMMENT '접근 금지 사이트 도메인, no_access_addr 테이블의 no_access_domain 참조',
    `access_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접근 시도 시간(5년 보관 후 자동 삭제)',
    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_number`) ON DELETE CASCADE,
    FOREIGN KEY (`no_access_domain`) REFERENCES `no_access_addr`(`no_access_domain`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. 온라인 IP 로그 테이블
CREATE TABLE `online_ip_log` (
    `employee_id` INT NOT NULL COMMENT '사원 번호, employees 테이블의 employee_id 참조',
    `online_ip` CHAR(15) NOT NULL COMMENT '접속 중인 PC',
    `login_time` DATETIME NOT NULL COMMENT '접속한 시간(5년 보관 후 자동 삭제)',
    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_number`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. 내부망에서 접속중인 사원 테이블
CREATE TABLE IF NOT EXISTS `online_ip` (
    `employee_id` INT NOT NULL COMMENT '사원 번호, employees 테이블의 employee_number 참조',
    `online_ip` CHAR(15) NOT NULL COMMENT '접속 중인 PC',
    `login_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접속한 시간',
    PRIMARY KEY (`employee_id`),
    CONSTRAINT `fk_online_ip_emp` FOREIGN KEY (`employee_id`) 
        REFERENCES `employees`(`employee_number`) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. 화이트 리스트 사이트 테이블
CREATE TABLE `whitelist_addr` (
    `whitelist_domain` VARCHAR(255) NOT NULL COMMENT '화이트 리스트 사이트 도메인',
    `deleted_at` DATE DEFAULT NULL COMMENT '화이트 리스트 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`whitelist_domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 만들어진 테이블에 필드 추가

-- 1. 가입 요청자 테이블에 '이름(name)' 컬럼 추가
-- 이메일(email) 컬럼 앞에 추가
ALTER TABLE `prospective_members`
ADD COLUMN `name` VARCHAR(50) NOT NULL COMMENT '가입 희망자 이름' AFTER `date_of_request`;

-- 2. 사원 테이블에 '이름(name)' 컬럼 추가
-- 입사일(hire_date) 컬럼 뒤에 추가
ALTER TABLE `employees`
ADD COLUMN `name` VARCHAR(50) NOT NULL COMMENT '사원 이름' AFTER `hire_date`;

-- 3. 사원 테이블에 '비밀번호(password)' 컬럼 추가
-- 사원 아이디(employee_id) 컬럼 뒤에 추가
ALTER TABLE `employees`
ADD COLUMN `password` VARCHAR(255) NOT NULL COMMENT '사원 비밀번호' AFTER `employee_id`;

-- 4. 접속중인 pc 테이블에 '맥주소(online_mac_addr)' 컬럼 추가
ALTER TABLE online_list 
ADD COLUMN online_mac_addr VARCHAR(17) NOT NULL COMMENT '내부망에서 접속 중인 PC 맥주소';

-- 5. 접속한 pc 로그 테이블에 '맥주소(online_mac_addr)' 컬럼 추가
ALTER TABLE online_list_log
ADD COLUMN online_mac_addr VARCHAR(17) NOT NULL COMMENT '내부망에서 접속 중인 PC 맥주소';

-- 테스트용 임시 직원 계정(관리자) 추가

INSERT INTO `employees` (
    `employee_id`, 
    `password`, 
    `name`, 
    `hire_date`, 
    `email`, 
    `address`, 
    `phone_number`, 
    `jumin_no`, 
    `is_manager`
) VALUES (
    'ubuntu',
    'ubuntu',
    '홍길동',
    CURRENT_DATE,
    'hong@naver.com',
    '서울',
    '01012345678',
    '9111111111111',
    TRUE
);

-- 테스트용 차단 도메인 추가
INSERT INTO no_access_addr (no_access_domain, no_access_ip) 
VALUES ('http://httpforever.com/', '0.0.0.0');


-- 자동 삭제 스케줄러 만들기

-- 1. DB 서버의 이벤트 스케줄러(자동 타이머) 기능 켜기
SET GLOBAL event_scheduler = ON;

-- 2. 혹시 이전에 만든 같은 이름의 스케줄러가 있다면 삭제 (중복 방지)
DROP EVENT IF EXISTS auto_purge_all_tables;

-- 3. 매일 1번씩 실행되는 통합 자동 삭제 스케줄러 생성
CREATE EVENT internal_db.auto_purge_all_tables
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
COMMENT '가입희망자(1개월) 및 임시삭제/로그 데이터(5년) 매일 자동 영구 삭제'
DO
BEGIN
    -- 1. 가입 요청자: 1달 경과 시 삭제 (변경 없음)
    DELETE FROM prospective_members 
    WHERE date_of_request <= DATE_SUB(NOW(), INTERVAL 1 MONTH);

    -- 2. 블랙리스트 임시 삭제 도메인: 5년 경과 시 영구 삭제 (테이블명 변경)
    DELETE FROM blacklist_addr 
    WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 3. 화이트리스트 임시 삭제 도메인: 5년 경과 시 영구 삭제 (신규 추가)
    DELETE FROM whitelist_addr 
    WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 4. 블랙리스트 접근 로그: 5년 경과 시 삭제 (테이블명 변경)
    DELETE FROM blacklist_addr_access_log 
    WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 5. 온라인 접속 로그: 5년 경과 시 삭제 (테이블명 변경)
    DELETE FROM online_list_log 
    WHERE login_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);
END



-- 직원 테이블 초기화
SET FOREIGN_KEY_CHECKS = 0;   -- 외래키 체크 해제
TRUNCATE TABLE employees;     -- 테이블 초기화 (AUTO_INCREMENT도 1로 리셋됨)
SET FOREIGN_KEY_CHECKS = 1;   -- 외래키 체크 다시 켜기

-- 내부망 로그인 초기화
TRUNCATE TABLE online_ip;

-- 직원 테이블 더미 데이터 150개 생성
INSERT INTO employees (
    employee_id, password, name, email, address, phone_number, jumin_no, hire_date, is_manager, deleted_at
)
WITH RECURSIVE dummy_gen AS (
    -- 1부터 시작
    SELECT 1 AS n
    UNION ALL
    -- 150이 될 때까지 1씩 증가시키며 반복
    SELECT n + 1 FROM dummy_gen WHERE n < 150
)
SELECT 
    CONCAT('admin', n),                           -- employee_id: admin1 ~ admin150
    'admin',                                      -- password: 모두 admin
    CONCAT('더미사원', n),                        -- name: 더미사원1 ~ 더미사원150
    CONCAT('admin', n, '@company.com'),           -- email: 중복 방지를 위해 번호 부여
    '더미 주소',                                  -- address: 공통 주소
    CONCAT('010', LPAD(n, 8, '0')),               -- phone_number: 01000000001 ~ (11자리 UNIQUE 맞춤)
    CONCAT('9901011', LPAD(n, 6, '0')),           -- jumin_no: 9901011000001 ~ (13자리 UNIQUE 맞춤)
    CURRENT_DATE,                                 -- hire_date: 오늘 날짜
    IF(n = 1, 1, 0),                              -- is_manager: n이 1(admin1)일 때만 1(True), 나머지는 0(False)
    NULL                                          -- deleted_at: 모두 현직(NULL)
FROM dummy_gen;


-- no_access_addr 테이블에 더미데이터 10개 생성
INSERT INTO no_access_addr (no_access_domain) VALUES 
('http://malicious-site01.com'),
('http://unwanted-ads02.net'),
('http://fake-login03.org'),
('http://spam-server04.co.kr'),
('http://phishing-test05.com'),
('http://illegal-stream06.net'),
('http://virus-dist07.org'),
('http://hacked-domain08.com'),
('http://block-target09.co.kr'),
('http://warning-page10.com');

-- no_access_addr 테이블에 데이터 추가
INSERT INTO no_access_addr (no_access_domain, deleted_at) 
VALUES ('http://neverssh.com/', NULL)
ON DUPLICATE KEY UPDATE deleted_at = NULL;

-- no_access_addr, no_access_addr_log 테이블의 online_ip 필드의 자료형 속성 변경(varchar->int)
-- 1. 줄바꿈(\n, \r) 및 양옆 공백 제거 후, 마지막 '.' 뒤의 값만 추출
UPDATE online_ip 
SET online_ip = TRIM(BOTH '\n' FROM TRIM(BOTH '\r' FROM TRIM(SUBSTRING_INDEX(online_ip, '.', -1))));

UPDATE online_ip_log 
SET online_ip = TRIM(BOTH '\n' FROM TRIM(BOTH '\r' FROM TRIM(SUBSTRING_INDEX(online_ip, '.', -1))));

-- 2. 'None'이나 빈칸 등 숫자가 아닌 잘못된 데이터는 삭제(또는 0으로 초기화)
DELETE FROM online_ip WHERE online_ip NOT REGEXP '^[0-9]+$';
DELETE FROM online_ip_log WHERE online_ip NOT REGEXP '^[0-9]+$';

-- 3. 이제 순수 숫자만 남았으므로 컬럼 타입을 INT로 안전하게 변경
ALTER TABLE online_ip MODIFY COLUMN online_ip INT NOT NULL;
ALTER TABLE online_ip_log MODIFY COLUMN online_ip INT NOT NULL;

-- 4. 변경 결과 확인 (Type이 int(11)로 나오면 성공!)
DESC online_ip;
DESC online_ip_log;

-- 테이블명, 컬럼명 변경
-- 1. 기존 테이블 이름 변경
RENAME TABLE no_access_addr TO blacklist_addr;
RENAME TABLE no_access_addr_log TO blacklist_addr_access_log;
RENAME TABLE online_ip TO online_list;
RENAME TABLE online_ip_log TO online_list_log;

-- 2. 컬럼명 변경 (no_access_domain -> blacklist_domain)
-- 기존 데이터 타입(VARCHAR)을 유지하면서 이름만 변경합니다.
ALTER TABLE blacklist_addr 
CHANGE no_access_domain blacklist_domain VARCHAR(255) NOT NULL;

ALTER TABLE blacklist_addr_access_log 
CHANGE no_access_domain blacklist_domain VARCHAR(255) NOT NULL;


-- 261019
-- web_access_log테이블 추가 및 online_list_log테이블에 id 필드 추가
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `web_access_log`;
DROP TABLE IF EXISTS `online_list_log`;
SET FOREIGN_KEY_CHECKS = 1;


-- 1. 온라인 IP 로그 테이블
CREATE TABLE `online_list_log` (
    `online_list_log_id` INT NOT NULL AUTO_INCREMENT COMMENT '온라인 로그 id',
    `employee_id` INT NOT NULL COMMENT '사원 번호, employees 테이블 참조',
    `online_ip` INT NOT NULL COMMENT '내부망 접속 PC IP 뒷번호',
    `login_time` DATETIME NOT NULL COMMENT '접속한 시간(5년 보관 후 자동 삭제)',
    `online_mac_addr` VARCHAR(17) NOT NULL COMMENT '내부망 접속 PC 맥주소',
    PRIMARY KEY (`online_list_log_id`),
    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_number`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 2. [신규] 웹 접근 로그 테이블 (`access_time`은 데이터 추가된 시간)
CREATE TABLE `web_access_log` (
    `web_access_log_id` INT NOT NULL AUTO_INCREMENT COMMENT '웹 접근 로그 id',
    `online_list_log_id` INT NOT NULL COMMENT 'online_list_log 테이블 참조',
    `target_url` VARCHAR(255) NOT NULL COMMENT '접근한 모든 도메인/URL',
    `access_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접근 시간(데이터 추가된 시간, 5년 보관 후 자동 삭제)',
    PRIMARY KEY (`web_access_log_id`),
    FOREIGN KEY (`online_list_log_id`) REFERENCES `online_list_log`(`online_list_log_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 261020
-- DB 테이블 구축 변경

USE internal_db;

-- =========================================================
-- 1. employees를 제외한 나머지 테이블 및 로그 삭제
-- =========================================================
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `online_ip_mac_mismatch_log`;
DROP TABLE IF EXISTS `blacklist_addr_access_log`;
DROP TABLE IF EXISTS `web_access_log`;
DROP TABLE IF EXISTS `online_list`;
DROP TABLE IF EXISTS `online_list_log`;
DROP TABLE IF EXISTS `blacklist_addr`;
DROP TABLE IF EXISTS `whitelist_addr`;
DROP TABLE IF EXISTS `prospective_members`;
-- (주의: employees 테이블은 보존합니다.)

SET FOREIGN_KEY_CHECKS = 1;


-- =========================================================
-- 2. employees 테이블 구조 변경 (otp_secret 필드 추가)
-- =========================================================
-- 이미 존재할 경우를 대비하여 안전하게 컬럼 추가 (없을 때만 추가되도록 하거나 ALTER 실행)
-- 참고: 만약 이미 otp_secret이 있다면 에러가 날 수 있으므로 체크 후 실행됩니다.
SET @dbname = DATABASE();
SET @tablename = "employees";
SET @columnname = "otp_secret";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @dbname
      AND TABLE_NAME = @tablename
      AND COLUMN_NAME = @columnname
  ) > 0,
  "SELECT 'Column already exists.'",
  "ALTER TABLE employees ADD COLUMN otp_secret VARCHAR(128) DEFAULT NULL COMMENT '구글 OTP 2차 인증용 시크릿 키';"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;


-- =========================================================
-- 3. 최신 엑셀 스키마 기반 나머지 테이블 재생성
-- =========================================================

-- 1. 가입 요청자 테이블
CREATE TABLE `prospective_members` (
    `members_table_id` INT NOT NULL AUTO_INCREMENT COMMENT '테이블 id',
    `member_id` VARCHAR(50) NOT NULL UNIQUE COMMENT '가입 요청 아이디',
    `password` VARCHAR(255) NOT NULL COMMENT '가입 요청 비밀번호',
    `name` VARCHAR(255) NOT NULL COMMENT '가입 희망자 이름',
    `date_of_request` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '가입 요청 일자(한달 후 자동 삭제)',
    `email` VARCHAR(255) NOT NULL UNIQUE COMMENT '이메일',
    `address` VARCHAR(255) NOT NULL COMMENT '실제 주소',
    `phone_number` CHAR(11) NOT NULL UNIQUE COMMENT '휴대 전화 번호',
    `jumin_no` CHAR(13) NOT NULL UNIQUE COMMENT '주민 번호',
    PRIMARY KEY (`members_table_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. 화이트리스트 사이트 테이블
CREATE TABLE `whitelist_addr` (
    `whitelist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `whitelist_domain` VARCHAR(255) NOT NULL UNIQUE COMMENT '화이트 리스트 사이트 도메인',
    `deleted_at` DATE DEFAULT NULL COMMENT '화이트 리스트 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`whitelist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. 블랙리스트 사이트 테이블
CREATE TABLE `blacklist_addr` (
    `blacklist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `blacklist_domain` VARCHAR(255) NOT NULL UNIQUE COMMENT '접근 금지(블랙 리스트) 사이트 도메인',
    `deleted_at` DATE DEFAULT NULL COMMENT '접근 금지 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`blacklist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. 온라인 IP 로그 테이블 (모든 접속 로그의 뿌리)
CREATE TABLE `online_list_log` (
    `online_list_log_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `employee_id` INT NOT NULL COMMENT '사원 번호, employees 테이블 참조',
    `online_ip` INT NOT NULL COMMENT '내부망에서 접속 중인 PC ip 뒷번호',
    `login_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접속한 시간(5년 보관 후 자동 삭제)',
    `online_mac_addr` VARCHAR(17) NOT NULL COMMENT '내부망에서 접속 중인 PC 맥주소',
    PRIMARY KEY (`online_list_log_id`),
    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_number`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. 내부망에서 접속 중인 사원 테이블
CREATE TABLE `online_list` (
    `employee_id` INT NOT NULL COMMENT '사원 번호, employees 테이블 참조',
    `online_ip` INT NOT NULL COMMENT '내부망에서 접속 중인 PC ip 뒷번호',
    `login_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접속한 시간',
    `online_mac_addr` VARCHAR(17) NOT NULL COMMENT '내부망에서 접속 중인 PC 맥주소',
    PRIMARY KEY (`employee_id`),
    FOREIGN KEY (`employee_id`) REFERENCES `employees`(`employee_number`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. 웹 접근 로그 테이블
CREATE TABLE `web_access_log` (
    `web_access_log_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `online_list_log_id` INT NOT NULL COMMENT 'online_list_log 참조',
    `target_url` VARCHAR(255) NOT NULL COMMENT '접근한 일반 도메인',
    `access_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접근 시간(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`web_access_log_id`),
    FOREIGN KEY (`online_list_log_id`) REFERENCES `online_list_log`(`online_list_log_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. 블랙리스트 접근 로그 테이블
CREATE TABLE `blacklist_addr_access_log` (
    `blacklist_addr_access_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `online_list_log_id` INT NOT NULL COMMENT 'online_list_log 참조',
    `blacklist_domain` VARCHAR(255) NOT NULL COMMENT '접근한 블랙리스트 도메인',
    `access_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접근 시간(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`blacklist_addr_access_id`),
    FOREIGN KEY (`online_list_log_id`) REFERENCES `online_list_log`(`online_list_log_id`) ON DELETE CASCADE,
    FOREIGN KEY (`blacklist_domain`) REFERENCES `blacklist_addr`(`blacklist_domain`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. [신규] IP-MAC 불일치/충돌 로그 테이블
CREATE TABLE `online_ip_mac_mismatch_log` (
    `online_ip_mac_mismatch_log_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `online_list_log_id` INT NOT NULL COMMENT 'online_list_log 테이블 참조',
    `mismatch_mac_addr` VARCHAR(17) NOT NULL COMMENT '맞지 않은 MAC주소',
    `insert_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '데이터가 추가된 시간(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`online_ip_mac_mismatch_log_id`),
    FOREIGN KEY (`online_list_log_id`) REFERENCES `online_list_log`(`online_list_log_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- 4. 자동 삭제 스케줄러 재설정
-- =========================================================
DELIMITER $$

-- 혹시 기존에 남아있을 수 있는 이벤트 삭제
DROP EVENT IF EXISTS auto_purge_all_tables$$

-- 이벤트 스케줄러 생성
CREATE EVENT internal_db.auto_purge_all_tables
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
COMMENT '가입희망자(1개월) 및 임시삭제/로그 데이터(5년) 매일 자동 영구 삭제'
DO
BEGIN
    DELETE FROM prospective_members 
    WHERE date_of_request <= DATE_SUB(NOW(), INTERVAL 1 MONTH);

    DELETE FROM blacklist_addr 
    WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    DELETE FROM whitelist_addr 
    WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    DELETE FROM online_list_log 
    WHERE login_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    DELETE FROM web_access_log 
    WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    DELETE FROM blacklist_addr_access_log 
    WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    DELETE FROM online_ip_mac_mismatch_log 
    WHERE insert_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);
END$$

-- 구분자를 다시 원래대로 복구
DELIMITER;


-- 261021
-- blacklist_addr 테이블에 source 필드 추가
-- blacklist_addr_access_log 테이블에 ai_score 필드 추가
USE internal_db;

-- =========================================================
-- 1. blacklist_addr 테이블에 source 필드 추가
-- =========================================================
ALTER TABLE `blacklist_addr` 
ADD COLUMN `source` VARCHAR(50) NOT NULL COMMENT 'USER/AI 중 어느 경로로 추가 되었는지에 대한 출처 정보';


-- =========================================================
-- 2. blacklist_addr_access_log 테이블에 ai_score 필드 추가 및 기존 데이터 기본값(-1) 설정
-- =========================================================
ALTER TABLE `blacklist_addr_access_log` 
ADD COLUMN `ai_score` DOUBLE DEFAULT -1 COMMENT 'AI가 차단한 경우, 위험도 점수를 기록, blacklist_addr 테이블을 참조하면 차단한 경우 = -1(DEFAULT)';


-- 3. dga_detection_log 테이블 생성
CREATE TABLE `dga_detection_log` (
    `dga_detection_log_id` INT NOT NULL AUTO_INCREMENT COMMENT 'AUTO_INCREMENT (기본키 ID)',
    `online_list_log_id` INT NOT NULL COMMENT 'online_list_log 참조 (어떤 사원의 세션인지 연결)',
    `domain` VARCHAR(255) NOT NULL COMMENT '탐지된 도메인 주소',
    `entropy_score` DOUBLE NOT NULL COMMENT '계산된 엔트로피(무작위성) 수치',
    `is_dga` BOOLEAN NOT NULL COMMENT 'DGA 악성 여부 (True / False)',
    `access_time` DATETIME NOT NULL COMMENT '탐지 및 접속 시도 시간(5년 후 자동 삭제)',
    PRIMARY KEY (`dga_detection_log_id`),
    FOREIGN KEY (`online_list_log_id`) REFERENCES `online_list_log`(`online_list_log_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 4. 자동 삭제 이벤트 스케줄러 변경 (dga_detection_log의 access_time 기준 5년 지난 데이터 삭제 포함)
SET GLOBAL event_scheduler = ON;

DROP EVENT IF EXISTS auto_purge_all_tables;

CREATE EVENT internal_db.auto_purge_all_tables
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
COMMENT '가입희망자(1개월) 및 임시삭제/로그 데이터(5년) 매일 자동 영구 삭제'
DO
BEGIN
    -- 1. 가입 요청자 테이블 (1개월 이상 경과)
    DELETE FROM prospective_members 
    WHERE date_of_request <= DATE_SUB(NOW(), INTERVAL 1 MONTH);

    -- 2. 블랙리스트 사이트 임시 삭제 데이터 (5년 이상 경과)
    DELETE FROM blacklist_addr 
    WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 3. 화이트리스트 사이트 임시 삭제 데이터 (5년 이상 경과)
    DELETE FROM whitelist_addr 
    WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 4. 온라인 IP 로그 (5년 이상 경과)
    DELETE FROM online_list_log 
    WHERE login_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 5. 웹 접근 로그 (5년 이상 경과)
    DELETE FROM web_access_log 
    WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 6. 블랙리스트 접근 로그 (5년 이상 경과)
    DELETE FROM blacklist_addr_access_log 
    WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 7. IP-MAC 불일치 로그 (5년 이상 경과)
    DELETE FROM online_ip_mac_mismatch_log 
    WHERE insert_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);

    -- 8. DGA 탐지 이력 로그 (5년 이상 경과)
    DELETE FROM dga_detection_log 
    WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);
END;



-- 5. 설비 구동 시간 테이블 생성
CREATE TABLE IF NOT EXISTS `eqp_run_time` (
    `eqp_run_time_id` INT NOT NULL AUTO_INCREMENT COMMENT 'eqp_run_time의 id',
    `work_start_time` TIME NOT NULL COMMENT '출근 시간',
    `work_end_time` TIME NOT NULL COMMENT '퇴근 시간',
    `waiting_time` TIME NOT NULL COMMENT '대기 시간 주기',
    PRIMARY KEY (`eqp_run_time_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 261026
USE internal_db;

-- whitelist_addr 테이블에 is_protected 필드 추가
ALTER TABLE `whitelist_addr` 
ADD COLUMN `is_protected` BOOLEAN NOT NULL DEFAULT 0 COMMENT '데이터 보호 처리';


-- 261027
USE internal_db;

-- 1. 고정 블랙리스트 테이블 생성
CREATE TABLE IF NOT EXISTS `fixed_blacklist_addr` (
    `fixed_blacklist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `fixed_blacklist_domain` VARCHAR(255) NOT NULL COMMENT 'KISA에서 내려받은 ai 교육용 blacklist 도메인',
    PRIMARY KEY (`fixed_blacklist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. 고정 화이트리스트 테이블 생성
CREATE TABLE IF NOT EXISTS `fixed_whitelist_addr` (
    `fixed_whitelist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `fixed_whitelist_domain` VARCHAR(255) NOT NULL COMMENT 'KISA에서 내려받은 ai 교육용 whitelist 도메인',
    PRIMARY KEY (`fixed_whitelist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SELECT 
    (SELECT COUNT(*) FROM fixed_blacklist_addr) AS fb_count,
    (SELECT COUNT(*) FROM fixed_whitelist_addr) AS fw_count;


-- 261028
USE internal_db;

-- 외래 키 체크 임시 해제
SET FOREIGN_KEY_CHECKS = 0;

-- 1. 기존 리스트 테이블명 변경 (whitelist_addr -> user_whitelist_addr, blacklist_addr -> user_blacklist_addr)
RENAME TABLE `whitelist_addr` TO `user_whitelist_addr`;
RENAME TABLE `blacklist_addr` TO `user_blacklist_addr`;

-- 2. User용 테이블 필드 수정 (PK명 변경, source 필드 제거)
-- 2-1. user_whitelist_addr 수정
ALTER TABLE `user_whitelist_addr` 
    CHANGE COLUMN `whitelist_id` `user_whitelist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id';

-- 2-2. user_blacklist_addr 수정 (source 필드 제거 및 PK명 변경)
ALTER TABLE `user_blacklist_addr` 
    CHANGE COLUMN `blacklist_id` `user_blacklist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    DROP COLUMN `source`;

-- 3. 이미 존재하는 고정 도메인 테이블의 비고(COMMENT) 갱신 (깃허브 출처 반영)
ALTER TABLE `fixed_blacklist_addr` 
    MODIFY COLUMN `fixed_blacklist_domain` VARCHAR(255) NOT NULL COMMENT '깃허브에서 내려받은 ai 교육용 blacklist 도메인';

ALTER TABLE `fixed_whitelist_addr` 
    MODIFY COLUMN `fixed_whitelist_domain` VARCHAR(255) NOT NULL COMMENT '깃허브에서 내려받은 ai 교육용 whitelist 도메인';

-- 4. AI용 블랙리스트/화이트리스트 테이블 신규 생성 (없는 경우에만 생성)
CREATE TABLE IF NOT EXISTS `AI_blacklist_addr` (
    `AI_blacklist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `blacklist_domain` VARCHAR(255) NOT NULL COMMENT '접근 금지(블랙 리스트) 사이트 도메인',
    `deleted_at` DATE DEFAULT NULL COMMENT '접근 금지 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    `risk_level` INT NOT NULL COMMENT '해당 주소를 AI모델이 구분한 위험도',
    PRIMARY KEY (`AI_blacklist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `AI_whitelist_addr` (
    `AI_whitelist_id` INT NOT NULL AUTO_INCREMENT COMMENT '현재 테이블 id',
    `whitelist_domain` VARCHAR(255) NOT NULL COMMENT '화이트 리스트 사이트 도메인',
    `deleted_at` DATE DEFAULT NULL COMMENT '화이트 리스트 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    `is_protected` BOOLEAN NOT NULL DEFAULT 0 COMMENT '데이터 보호 처리',
    PRIMARY KEY (`AI_whitelist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 외래 키 체크 복구
SET FOREIGN_KEY_CHECKS = 1;