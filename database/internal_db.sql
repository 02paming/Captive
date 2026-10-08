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