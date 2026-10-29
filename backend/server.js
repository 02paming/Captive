/**
 * @file server.js
 * @description 백엔드 서버의 진입점(Entry Point)입니다.
 * 프론트엔드(React)에서 들어오는 요청을 받아 MySQL 데이터베이스와 통신한 후 결과를 돌려줍니다.
 */

// 1. 필요한 외부 모듈 불러오기
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // 비동기(Promise) 방식으로 DB를 처리하기 위한 모듈

// 2. 익스프레스 앱 생성 및 포트 설정
const app = express();
const PORT = 5000; // 프론트엔드(5173)와 충돌하지 않도록 백엔드는 5000번 포트를 사용합니다.

// 3. 미들웨어(Middleware) 세팅
// CORS: 서로 다른 포트(5173 <-> 5000) 간의 데이터 통신을 허용해주는 보안 설정
app.use(cors());
// 클라이언트가 JSON 형태로 보낸 데이터(req.body)를 서버가 읽을 수 있게 변환해줌
app.use(express.json());

// 4. MySQL 데이터베이스 연결 풀(Pool) 세팅
// 연결 풀(Pool)이란? DB 연결을 요청마다 새로 맺고 끊는 대신, 
// 미리 여러 개를 만들어두고 빌려쓰는 효율적인 서버 관리 방식입니다.
const db = mysql.createPool({
  host: 'localhost',         // DB가 설치된 컴퓨터 주소
  user: 'root',              // MySQL 접속 계정명
  password: '비밀번호입력',     // MySQL 비밀번호 (팀원들 PC 환경에 맞게 수정 필요)
  database: 'securetech_db', // 연결할 데이터베이스 이름 (database/test.sql 기반)
  waitForConnections: true,  // 연결 풀이 꽉 찼을 때 새 요청을 대기시킬지 여부
  connectionLimit: 10,       // 동시에 유지할 최대 연결 수 (기본 10개)
  queueLimit: 0              // 대기열 수 제한 (0은 무제한)
});

// 5. 서버 작동 테스트 API
// 브라우저에서 http://localhost:5000/api/health 에 접속하면 서버 상태를 확인할 수 있습니다.
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: '✅ 백엔드 서버 및 DB 통신 API가 정상 작동 중입니다.' });
});

// ==========================================
// 💡 [API 라우터 영역] 
// 앞으로 프론트엔드 파일들을 점검하면서 필요한 API(게시판, 결재 등)를 이곳에 하나씩 추가할 예정입니다.
// ==========================================

/**
 * [API] 로그인 검증
 * 프론트엔드의 LoginPage.jsx에서 넘겨준 사번과 비밀번호를 DB와 대조합니다.
 */
app.post('/api/login', async (req, res) => {
  // 프론트에서 보낸 데이터(req.body)에서 사번과 비밀번호 추출
  const { emp_id, password } = req.body;

  try {
    // DB의 users 테이블에서 해당 사번(emp_id)을 가진 유저 검색
    // ? 부분에 emp_id가 안전하게 치환되어 들어갑니다. (SQL 인젝션 방어)
    const [rows] = await db.query('SELECT * FROM users WHERE emp_id = ?', [emp_id]);

    // 유저가 존재하고, 비밀번호가 일치하는지 확인 
    // (주의: 실무에서는 평문 비교가 아닌 암호화 해시 비교를 사용해야 하지만, 현재는 직관성을 위해 평문으로 둡니다)
    if (rows.length > 0 && rows[0].password === password) {
      const user = rows[0];
      // 보안을 위해 비밀번호는 쏙 빼고 필요한 정보만 프론트로 넘겨줍니다.
      res.json({
        success: true,
        user: { emp_id: user.emp_id, name: user.name, role: user.role, department: user.department }
      });
    } else {
      // 정보가 틀렸을 때 프론트에 401(권한 없음) 상태 코드 전달
      res.status(401).json({ success: false, message: '사번 또는 비밀번호가 일치하지 않습니다.' });
    }
  } catch (error) {
    console.error('로그인 DB 쿼리 에러:', error);
    res.status(500).json({ success: false, message: '서버 에러가 발생했습니다.' });
  }
});

// 6. 서버 실행
app.listen(PORT, () => {
  console.log(`🚀 백엔드 서버가 http://localhost:${PORT} 에서 성공적으로 실행되었습니다.`);
});
