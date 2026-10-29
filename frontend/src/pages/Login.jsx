import React, { useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const Login = () => {
  const [empId, setEmpId] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault(); // 폼 제출 시 새로고침 방지

    // 1. 빈칸 검사
    if (!empId || !password) {
      alert('아이디와 비밀번호를 모두 입력해주세요.');
      return;
    }

    try {
      // 2. 백엔드로 로그인 요청
      const response = await axios.post('http://127.0.0.1:8000/auth/login/', {
        employee_id: empId, 
        password: password
      });

      // 3. 성공 처리
      if (response.data.status === 'success') {
        localStorage.setItem('user', JSON.stringify(response.data.user));
        window.location.href = '/'; // 로그인 성공 시 대시보드로 즉시 이동
      } else {
        alert(response.data.message || '아이디 또는 비밀번호가 일치하지 않습니다.');
      }
      
    } catch (error) {
      // 4. 에러 (실패) 처리
      console.error("로그인 에러:", error);

      // (1) 서버가 꺼져있거나 통신 자체가 안 될 때
      if (!error.response) {
        alert('백엔드 서버와 통신할 수 없습니다.\n파이참(PyCharm)에서 서버(runserver)가 켜져 있는지 확인해 주세요!');
        return;
      }

      // (2) 아이디가 없거나 비밀번호가 틀려서 백엔드가 에러를 뱉었을 때
      const serverData = error.response.data;
      if (serverData && serverData.message) {
        alert(serverData.message);
      } else if (serverData && serverData.error) {
        alert(serverData.error);
      } else {
        alert('등록되지 않은 아이디이거나 비밀번호가 일치하지 않습니다.');
      }
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '100px auto', padding: '30px', textAlign: 'center', backgroundColor: 'white', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}>
      <h2 style={{ marginBottom: '30px', color: '#1e293b' }}>🔒 인트라넷 로그인</h2>
      
      <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
        <input 
          type="text" 
          placeholder="개인 아이디 (ID)" 
          value={empId} 
          onChange={(e) => setEmpId(e.target.value)} 
          className="custom-input" 
        />
        <input 
          type="password" 
          placeholder="비밀번호" 
          value={password} 
          onChange={(e) => setPassword(e.target.value)} 
          className="custom-input" 
        />
        <button type="submit" className="btn-primary" style={{ padding: '14px', marginTop: '10px' }}>
          로그인
        </button>
      </form>
      
      <div style={{ marginTop: '20px' }}>
        <p style={{ fontSize: '14px', color: '#64748b' }}>
          아직 계정이 없으신가요? <Link to="/signup" style={{ color: '#38bdf8', textDecoration: 'none', fontWeight: 'bold' }}>사원 가입 신청</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;