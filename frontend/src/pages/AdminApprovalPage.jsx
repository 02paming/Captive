/**
 * @file AdminApprovalPage.jsx
 * @description [관리자 전용] 인사/계정 관리 페이지입니다.
 * 가입을 요청한 사원들의 계정을 승인하거나 권한을 부여하는 역할을 합니다.
 * (💡 Layout 래퍼를 사용하므로 사이드바/헤더 코드는 작성하지 않습니다.)
 */

import React, { useState } from 'react';

const AdminApprovalPage = () => {
  const [pendingUsers, setPendingUsers] = useState([
    { id: 1, name: '김신입', phone: '010-1111-2222', email: 'newbie@naver.com', department: '영업팀', status: '대기' }
  ]);

  const handleApprove = (id, email) => {
    const accountId = email.split('@')[0];
    const currentYear = new Date().getFullYear();
    const randomNum = String(Math.floor(Math.random() * 1000)).padStart(3, '0');
    const newEmpId = `${currentYear}${randomNum}`;
    const companyEmail = `${accountId}@GT.co.kr`;

    alert(`✅ 계정 승인 및 발급 완료!\n\n- 직원명: 김신입\n- 로그인 ID: ${accountId}\n- 발급된 사번: ${newEmpId}\n- 회사 메일: ${companyEmail}\n\n* 직원에게 승인 알림 메일이 발송됩니다.`);

    setPendingUsers(prev => prev.filter(user => user.id !== id));
  };

  return (
    <div className="admin-container">

      {/* ★ IT 자산 관리 페이지와 완벽하게 동일한 래퍼 구조입니다. (임의로 넣었던 글자색 제거) */}
      <div className="admin-header-area" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3>인사/계정 관리 (가입 대기열)</h3>
          <p>신규 가입자의 계정을 승인하면 사번과 사내 이메일이 자동 발급됩니다.</p>
        </div>
      </div>

      {/* 테이블 영역 */}
      <table className="board-table">
        <thead>
          <tr>
            <th>신청자 (이름)</th>
            <th>연락처</th>
            <th>이메일 (ID 기반)</th>
            <th>부서</th>
            <th>상태</th>
            <th>관리</th>
          </tr>
        </thead>
        <tbody>
          {pendingUsers.length > 0 ? (
            pendingUsers.map(user => (
              <tr key={user.id}>
                <td style={{ fontWeight: 'bold' }}>{user.name}</td>
                <td>{user.phone}</td>
                <td style={{ color: '#2980b9' }}>{user.email}</td>
                <td>{user.department}</td>
                <td><span className="status-badge pending">{user.status}</span></td>
                <td>
                  <button
                    style={{ backgroundColor: '#27ae60', color: 'white', border: 'none', padding: '6px 14px', borderRadius: '5px', cursor: 'pointer', fontWeight: 'bold' }}
                    onClick={() => handleApprove(user.id, user.email)}
                  >
                    가입 승인
                  </button>
                </td>
              </tr>
            ))
          ) : (
            <tr><td colSpan="6" style={{ textAlign: 'center', padding: '40px' }}>가입 대기 중인 계정이 없습니다.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default AdminApprovalPage;
