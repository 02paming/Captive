<<<<<<< HEAD
/**
 * @file MyPage.jsx
 * @description 임직원 본인의 정보를 확인하고 수정(비밀번호 변경 등)하는 마이페이지입니다.
 */

import React, { useState } from 'react';
import './MyPage.css'; // 필요 시 CSS 생성

const MyPage = () => {
  // 세션에 저장된 내 정보 불러오기
  const currentUser = JSON.parse(sessionStorage.getItem('loggedInUser')) || {};

  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: 비밀번호 변경 요청을 '/api/users/me/password' (PUT) 로 전송합니다.
  const [newPassword, setNewPassword] = useState('');

  const handlePasswordChange = (e) => {
    e.preventDefault();
    if (!newPassword) return;

    // API 통신 로직이 들어갈 자리
    alert('비밀번호가 성공적으로 변경되었습니다. (테스트)');
    setNewPassword('');
  };

  return (
    <div className="mypage-container" style={{ padding: '20px' }}>
      <div style={{ marginBottom: '20px', borderBottom: '2px solid #ecf0f1', paddingBottom: '10px' }}>
        <h3 style={{ margin: 0 }}>내 정보 관리 (My Page)</h3>
      </div>

      <div style={{ display: 'flex', gap: '30px' }}>
        {/* 1. 기본 정보 카드 */}
        <div style={{ flex: 1, backgroundColor: 'white', padding: '25px', borderRadius: '8px', border: '1px solid #e0e0e0' }}>
          <h4 style={{ marginTop: 0, color: '#3498db' }}>사원 기본 정보</h4>
          <p><strong>사원번호 (ID):</strong> {currentUser.emp_id}</p>
          <p><strong>이름:</strong> {currentUser.name}</p>
          <p><strong>소속 부서:</strong> {currentUser.department}</p>
          <p><strong>시스템 권한:</strong> <span className={`status-badge ${currentUser.role === '관리자' ? 'approved' : 'pending'}`}>{currentUser.role}</span></p>
        </div>

        {/* 2. 비밀번호 변경 카드 */}
        <div style={{ flex: 1, backgroundColor: 'white', padding: '25px', borderRadius: '8px', border: '1px solid #e0e0e0' }}>
          <h4 style={{ marginTop: 0, color: '#e74c3c' }}>비밀번호 변경</h4>
          <form onSubmit={handlePasswordChange}>
            <input
              type="password"
              placeholder="새로운 비밀번호 입력"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              style={{ width: '100%', padding: '10px', marginBottom: '15px', border: '1px solid #bdc3c7', borderRadius: '4px' }}
            />
            <button type="submit" style={{ width: '100%', padding: '10px', backgroundColor: '#2c3e50', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
              비밀번호 변경하기
            </button>
          </form>
=======
import React, { useState, useEffect } from 'react';
import axios from 'axios';

const MyPage = () => {
  const [info, setInfo] = useState(null);
  const [editForm, setEditForm] = useState({ phone_number: '', address: '' });
  const user = JSON.parse(localStorage.getItem('user'));

  useEffect(() => {
    if (user) {
      axios.post('http://127.0.0.1:8000/auth/me/', { employee_id: user.emp_id })
        .then(res => {
          setInfo(res.data.data);
          setEditForm({ phone_number: res.data.data.phone_number, address: res.data.data.address });
        })
        .catch(err => console.error(err));
    }
  }, [user]);

  const handleUpdate = async () => {
    try {
      await axios.post('http://127.0.0.1:8000/employees/update/', {
        employee_id: user.emp_id,
        ...editForm
      });
      alert('내 정보가 안전하게 수정되었습니다.');
    } catch (error) {
      alert('정보 수정 중 오류가 발생했습니다.');
    }
  };

  if (!info) return <div>로딩 중...</div>;

  return (
    <div className="dashboard-container" style={{ maxWidth: '600px', marginTop: '20px' }}>
      <div className="card">
        <h2 className="page-title" style={{ borderBottom: '2px solid #f1f5f9', paddingBottom: '15px', marginBottom: '20px' }}>
          🧑‍💻 내 정보 관리 (마이페이지)
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px', backgroundColor: '#f8fafc', borderRadius: '8px' }}>
            <span style={{ fontWeight: 'bold', color: '#475569' }}>공식 사번</span>
            <span className="badge badge-green">{info.emp_code}</span>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px' }}>
            <span style={{ fontWeight: 'bold', color: '#475569' }}>이름 / 아이디</span>
            <span style={{ color: '#334155' }}>{info.name} ({info.employee_id})</span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px' }}>
            <span style={{ fontWeight: 'bold', color: '#475569' }}>회사 이메일</span>
            <span style={{ color: '#334155' }}>{info.email}</span>
          </div>

          <hr style={{ border: '0', borderTop: '1px solid #e2e8f0', margin: '10px 0' }} />
          <p style={{ fontSize: '13px', color: '#64748b', margin: '0 0 10px 0' }}>* 아래 항목만 개인이 직접 수정할 수 있습니다.</p>

          <div>
            <label style={{ fontSize: '14px', fontWeight: 'bold', color: '#475569' }}>연락처 수정</label>
            <input type="text" value={editForm.phone_number} onChange={(e) => setEditForm({...editForm, phone_number: e.target.value})} className="custom-input" style={{ width: '95%', marginTop: '5px' }} />
          </div>
          
          <div>
            <label style={{ fontSize: '14px', fontWeight: 'bold', color: '#475569' }}>거주지 주소 수정</label>
            <input type="text" value={editForm.address} onChange={(e) => setEditForm({...editForm, address: e.target.value})} className="custom-input" style={{ width: '95%', marginTop: '5px' }} />
          </div>

          <button onClick={handleUpdate} className="btn-primary" style={{ marginTop: '20px', padding: '12px' }}>
            수정 내용 저장
          </button>
>>>>>>> cff693a29f43b6f65ebdb4da4834b5bc7865f194
        </div>
      </div>
    </div>
  );
};

<<<<<<< HEAD
export default MyPage;
=======
export default MyPage;
>>>>>>> cff693a29f43b6f65ebdb4da4834b5bc7865f194
