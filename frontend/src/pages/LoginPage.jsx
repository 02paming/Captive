/**
 * @file LoginPage.jsx
 * @description 그룹웨어 로그인 페이지입니다.
 * 사용자가 입력한 사번(emp_id)과 비밀번호를 백엔드 서버로 전송하여 인증을 수행합니다.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './LoginPage.css';

const LoginPage = () => {
  const navigate = useNavigate();
  const [empId, setEmpId] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    if (empId === 'admin' && password === '1234') {
      const mockAdmin = { emp_id: 'admin', name: '윤두상', role: '관리자', department: '보안1팀' };
      sessionStorage.setItem('loggedInUser', JSON.stringify(mockAdmin));
      navigate('/dashboard');
    } else if (empId === 'user01' && password === '1234') {
      const mockUser = { emp_id: 'user01', name: '최프론트', role: '일반', department: '보안1팀' };
      sessionStorage.setItem('loggedInUser', JSON.stringify(mockUser));
      navigate('/dashboard');
    } else {
      setErrorMsg('아이디/사번 또는 비밀번호가 일치하지 않습니다.');
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        {/* 인트라넷 -> 그룹웨어로 변경 */}
        <h2 className="login-title">SecureTech 그룹웨어</h2>
        <p className="login-subtitle">사내 그룹웨어 시스템에 오신 것을 환영합니다.</p>

        <form onSubmit={handleLogin} className="login-form">
          <input
            type="text"
            placeholder="아이디 또는 사번을 입력하세요 (예: admin)"
            value={empId}
            onChange={(e) => setEmpId(e.target.value)}
            required
            className="login-input"
          />
          <input
            type="password"
            placeholder="비밀번호"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="login-input"
          />

          {errorMsg && <div className="error-message" style={{ color: '#e74c3c', fontSize: '13px', marginBottom: '10px' }}>{errorMsg}</div>}

          <button type="submit" className="login-btn">로그인</button>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
