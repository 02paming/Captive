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
    `no_access_domain` VARCHAR(255) NOT NULL COMMENT '접근 금지 사이트 주소, 하나의 ip에 여러 개의 DNS 주소가 있을 수 있음',
    `deleted_at` DATE DEFAULT NULL COMMENT '접근 금지 사이트 임시 삭제 일자(5년 보관 후 자동 삭제)',
    PRIMARY KEY (`no_access_domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. 접근 금지 사이트 로그 테이블
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

CREATE TABLE IF NOT EXISTS `online_ip` (
    `employee_id` INT NOT NULL COMMENT '사원 번호, employees 테이블의 employee_number 참조',
    `online_ip` CHAR(15) NOT NULL COMMENT '접속 중인 PC',
    `login_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '접속한 시간',
    PRIMARY KEY (`employee_id`),
    CONSTRAINT `fk_online_ip_emp` FOREIGN KEY (`employee_id`) 
        REFERENCES `employees`(`employee_number`) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 만들어진 테이블에 필드 추가

-- 6. 가입 요청자 테이블에 '이름(name)' 컬럼 추가
-- 이메일(email) 컬럼 앞에 추가합니다.
ALTER TABLE `prospective_members`
ADD COLUMN `name` VARCHAR(50) NOT NULL COMMENT '가입 희망자 이름' AFTER `date_of_request`;

-- 7. 사원 테이블에 '이름(name)' 컬럼 추가
-- 입사일(hire_date) 컬럼 뒤에 추가합니다.
ALTER TABLE `employees`
ADD COLUMN `name` VARCHAR(50) NOT NULL COMMENT '사원 이름' AFTER `hire_date`;

-- 8. 사원 테이블에 '비밀번호(password)' 컬럼 추가
-- 사원 아이디(employee_id) 컬럼 뒤에 추가합니다.
ALTER TABLE `employees`
ADD COLUMN `password` VARCHAR(255) NOT NULL COMMENT '사원 비밀번호' AFTER `employee_id`;


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
    DELETE FROM internal_db.prospective_members WHERE date_of_request <= DATE_SUB(CURDATE(), INTERVAL 1 MONTH);
    DELETE FROM internal_db.no_access_addr_log WHERE access_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);
    DELETE FROM internal_db.online_ip_log WHERE login_time <= DATE_SUB(NOW(), INTERVAL 5 YEAR);
    DELETE FROM internal_db.employees WHERE deleted_at IS NOT NULL AND deleted_at <= DATE_SUB(CURDATE(), INTERVAL 5 YEAR);
    DELETE FROM internal_db.no_access_addr WHERE deleted_at IS NOT NULL AND deleted_at <= DATE_SUB(CURDATE(), INTERVAL 5 YEAR);
END