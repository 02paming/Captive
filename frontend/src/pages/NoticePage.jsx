/**
 * @file NoticePage.jsx
 * @description 전사 공지사항을 확인하는 페이지입니다.
 * (💡 BoardPage와 유사하지만, 관리자만 글을 쓸 수 있는 특수한 성격을 가집니다.)
 */

import React, { useState } from 'react';
import './BoardPage.css';

const NoticePage = () => {
  // 현재 로그인한 유저 정보 확인 (글쓰기 버튼 권한 체크용)
  const currentUser = JSON.parse(sessionStorage.getItem('loggedInUser')) || {};

  const [notices, setNotices] = useState([
    { post_id: 1, title: '[필독] 사내 보안 관제 시스템 오픈 안내', author: '관리자', date: '2026-09-29', views: 152 },
    { post_id: 2, title: '10월 전사 휴무일 및 연차 사용 안내', author: '인사팀', date: '2026-09-25', views: 304 }
  ]);

  return (
    <div className="board-content-wrapper">
      <div className="board-header-area" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h3>공지사항</h3>
          <p>회사의 주요 소식과 안내 사항을 꼭 확인해 주세요.</p>
        </div>

        {/* ★ 관리자일 경우에만 글쓰기 버튼 노출 */}
        {currentUser.role === '관리자' && (
          <button
            style={{ backgroundColor: '#3498db', color: 'white', border: 'none', padding: '10px 20px', borderRadius: '5px', fontWeight: 'bold', cursor: 'pointer' }}
          >
            ✏️ 공지 작성
          </button>
        )}
      </div>

      <table className="board-table">
        <thead>
          <tr>
            <th>번호</th>
            <th style={{ width: '60%' }}>제목</th>
            <th>작성자</th>
            <th>작성일</th>
            <th>조회</th>
          </tr>
        </thead>
        <tbody>
          {notices.map(notice => (
            <tr key={notice.post_id} style={{ backgroundColor: '#fdfbfb' }}>
              <td style={{ color: '#e74c3c', fontWeight: 'bold' }}>공지</td>
              <td style={{ textAlign: 'left', fontWeight: 'bold', cursor: 'pointer' }}>{notice.title}</td>
              <td>{notice.author}</td>
              <td>{notice.date}</td>
              <td>{notice.views}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default NoticePage;
