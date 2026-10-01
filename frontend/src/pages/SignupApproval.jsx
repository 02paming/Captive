import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SignupApproval = () => {
  const [pendingUsers, setPendingUsers] = useState([]);

  const fetchPendingUsers = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/auth/pending/');
      setPendingUsers(response.data);
    } catch (error) {
      console.error('대기자 목록을 불러오는 중 오류 발생:', error);
    }
  };

  useEffect(() => {
    fetchPendingUsers();
  }, []);

  const handleApprove = async (memberId) => {
    if (!window.confirm('정말로 이 사용자의 가입을 승인하시겠습니까?')) return;
    try {
      const res = await axios.post('http://127.0.0.1:8000/auth/approve/', { member_id: memberId });
      if (res.data.status === 'success') {
        alert(res.data.message);
        fetchPendingUsers(); // 목록 새로고침
      }
    } catch (error) {
      alert('승인 처리 중 오류가 발생했습니다.');
    }
  };

  const handleReject = async (memberId) => {
    if (!window.confirm('가입 요청을 거절하고 삭제하시겠습니까?')) return;
    try {
      const res = await axios.post('http://127.0.0.1:8000/auth/reject/', { member_id: memberId });
      if (res.data.status === 'success') {
        alert(res.data.message);
        fetchPendingUsers();
      }
    } catch (error) {
      alert('거절 처리 중 오류가 발생했습니다.');
    }
  };

  return (
    <div className="dashboard-container">
      <div className="page-header">
        <h2 className="page-title">✅ 가입 승인 관리</h2>
        <p className="page-subtitle">회원가입을 요청한 대기자의 신원을 확인하고 사내망 접근 권한을 부여합니다.</p>
      </div>

      <div className="card">
        <table className="custom-table">
          <thead>
            <tr>
              <th>신청일자</th>
              <th>이름</th>
              <th>사번(ID)</th>
              <th>연락처</th>
              <th>승인/거절</th>
            </tr>
          </thead>
          <tbody>
            {pendingUsers.length > 0 ? pendingUsers.map((user) => (
              <tr key={user.member_id}>
                <td style={{ color: '#64748b' }}>{user.date_of_request}</td>
                <td style={{ fontWeight: 'bold' }}>{user.name}</td>
                <td>{user.member_id}</td>
                <td>{user.phone_number}</td>
                <td>
                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                    <button onClick={() => handleApprove(user.member_id)} className="badge badge-green" style={{ border: 'none', cursor: 'pointer', padding: '6px 12px' }}>
                      승인
                    </button>
                    <button onClick={() => handleReject(user.member_id)} className="badge badge-red" style={{ border: 'none', cursor: 'pointer', padding: '6px 12px' }}>
                      거절
                    </button>
                  </div>
                </td>
              </tr>
            )) : (
              <tr><td colSpan="5" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>현재 가입 대기 중인 인원이 없습니다.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SignupApproval;