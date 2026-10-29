/**
 * @file SignupPage.jsx
 * @description 신규 입사자 계정 신청 페이지입니다.
 * 신청된 데이터는 AdminApprovalPage(가입 대기열)로 넘어가 관리자 승인 후 활성화됩니다.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './LoginPage.css';

const SignupPage = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({ name: '', phone: '', email: '', password: '', department: '' });

  const handleSubmit = (e) => {
    e.preventDefault();
    // 이메일 앞자리 추출 (예: test@gmail.com -> test)
    const requestedId = formData.email.split('@')[0];

    alert(`계정 신청 완료!\n입력하신 이메일의 앞자리(${requestedId})가 계정 ID로 활용되며, 관리자 승인 시 사번과 사내 메일(@GT.co.kr)이 자동 발급됩니다.`);
    navigate('/login');
  };

  return (
    <div className="login-container">
      {/* 폼이 넉넉하게 들어가도록 박스 가로 크기(maxWidth)를 살짝 키웠습니다 */}
      <div className="login-box" style={{ maxWidth: '450px', padding: '40px' }}>
        <h2 className="login-title">입사자 계정 신청</h2>
        <p className="login-subtitle">승인 완료 시 사번과 사내 메일이 자동 부여됩니다.</p>

        <form onSubmit={handleSubmit} className="login-form">
          <input type="text" placeholder="이름 (실명)" required onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="login-input" />
          <input type="tel" placeholder="연락처 (예: 010-1234-5678)" required onChange={(e) => setFormData({ ...formData, phone: e.target.value })} className="login-input" />
          <input type="email" placeholder="자주 쓰는 이메일 (@ 앞부분이 ID로 사용됨)" required onChange={(e) => setFormData({ ...formData, email: e.target.value })} className="login-input" />
          <input type="password" placeholder="비밀번호 설정" required onChange={(e) => setFormData({ ...formData, password: e.target.value })} className="login-input" />

          <select required onChange={(e) => setFormData({ ...formData, department: e.target.value })} className="login-input" style={{ appearance: 'auto' }}>
            <option value="">소속 부서 선택</option>
            <option value="보안개발실">보안개발실</option>
            <option value="경영지원실">경영지원실</option>
          </select>

          <button type="submit" className="login-btn">계정 신청하기</button>
          <button type="button" onClick={() => navigate('/')} className="login-btn" style={{ backgroundColor: '#ecf0f1', color: '#7f8c8d', marginTop: '0' }}>취소 및 뒤로가기</button>
        </form>
      </div>
    </div>
  );
};

export default SignupPage;
