/**
 * @file ApprovalPage.jsx
 * @description 전자결재 메인 페이지입니다.
 * 본인이 상신한 기안 문서들의 목록과 현재 결재 진행 상태(대기/승인/반려)를 확인합니다.
 */

import React, { useState } from 'react';
import './ApprovalPage.css';

const ApprovalPage = () => {
  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: 로그인한 유저의 사번을 보내 '/api/approvals/my' (GET) 데이터를 가져옵니다.
  const [myApprovals, setMyApprovals] = useState([
    { doc_id: 101, title: '서버 증설 요청건', type: '기안서', status: '대기', date: '2026-09-29' },
    { doc_id: 98, title: '추석 연휴 연차 신청', type: '휴가신청서', status: '승인', date: '2026-09-15' }
  ]);

  return (
    <div className="approval-container">
      <div className="approval-header-area" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3>전자결재 (내 기안 문서)</h3>
          <p>내가 상신한 결재 문서들의 진행 상황을 확인합니다.</p>
        </div>
        <button
          style={{ backgroundColor: '#3498db', color: 'white', border: 'none', padding: '10px 20px', borderRadius: '5px', fontWeight: 'bold', cursor: 'pointer' }}
        >
          + 새 결재 기안하기
        </button>
      </div>

      <table className="board-table">
        <thead>
          <tr>
            <th>문서번호</th>
            <th>양식</th>
            <th style={{ width: '40%' }}>제목</th>
            <th>기안일자</th>
            <th>결재상태</th>
          </tr>
        </thead>
        <tbody>
          {myApprovals.map(doc => (
            <tr key={doc.doc_id}>
              <td>{doc.doc_id}</td>
              <td>{doc.type}</td>
              <td style={{ textAlign: 'left', fontWeight: 'bold', cursor: 'pointer' }}>{doc.title}</td>
              <td>{doc.date}</td>
              <td>
                {/* 상태값에 따라 동적으로 CSS 클래스를 부여하여 색상을 다르게 표시합니다 */}
                <span className={`status-badge ${doc.status === '승인' ? 'approved' : 'pending'}`}>
                  {doc.status}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ApprovalPage;
