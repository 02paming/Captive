/**
 * @file DashboardPage.jsx
 * @description 인트라넷 로그인 후 접속되는 메인 대시보드 페이지입니다.
 * 공지사항, 결재 대기 문서 등 주요 업무 현황을 요약해서(Widget 형태로) 보여줍니다.
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './DashboardPage.css'; // 대시보드 위젯 전용 CSS

const DashboardPage = () => {
  const navigate = useNavigate();
  const currentUser = JSON.parse(sessionStorage.getItem('loggedInUser')) || { name: '임직원' };

  // 💡 [DB 연동 포인트] 
  // 백엔드 연동 시: '/api/dashboard/summary' (GET)를 호출하여 아래 3가지 위젯 데이터를 한 번에 가져옵니다.
  const [recentNotices, setRecentNotices] = useState([
    { id: 1, title: '[필독] 사내 보안 관제 시스템 오픈 안내', date: '2026-09-29' },
    { id: 2, title: '10월 전사 휴무일 및 연차 사용 안내', date: '2026-09-25' }
  ]);

  const [pendingApprovals, setPendingApprovals] = useState([
    { id: 101, title: '서버 증설 요청건', status: '결재 대기' }
  ]);

  return (
    <div className="dashboard-container">
      <div className="dashboard-welcome" style={{ marginBottom: '30px', padding: '20px', backgroundColor: '#f8f9fa', borderRadius: '8px', borderLeft: '5px solid #3498db' }}>
        <h3 style={{ margin: 0, color: '#2c3e50' }}>환영합니다, {currentUser.name} 님!</h3>
        <p style={{ margin: '5px 0 0 0', color: '#7f8c8d' }}>오늘도 안전하고 활기찬 하루 보내시길 바랍니다.</p>
      </div>

      {/* 대시보드 위젯 그리드 (가로 2단 또는 3단 배치) */}
      <div className="widget-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>

        {/* 위젯 1: 최근 공지사항 */}
        <div className="widget-card" style={{ padding: '20px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '2px solid #ecf0f1', paddingBottom: '10px', marginBottom: '15px' }}>
            <h4 style={{ margin: 0 }}>최근 공지사항</h4>
            <span style={{ cursor: 'pointer', color: '#3498db', fontSize: '12px' }} onClick={() => navigate('/notice')}>+ 더보기</span>
          </div>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {recentNotices.map(notice => (
              <li key={notice.id} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', fontSize: '14px' }}>
                <span style={{ cursor: 'pointer' }}>{notice.title}</span>
                <span style={{ color: '#95a5a6', fontSize: '12px' }}>{notice.date}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* 위젯 2: 내 결재 진행 현황 */}
        <div className="widget-card" style={{ padding: '20px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '2px solid #ecf0f1', paddingBottom: '10px', marginBottom: '15px' }}>
            <h4 style={{ margin: 0 }}>나의 결재 대기함</h4>
            <span style={{ cursor: 'pointer', color: '#3498db', fontSize: '12px' }} onClick={() => navigate('/approval')}>+ 더보기</span>
          </div>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {pendingApprovals.map(doc => (
              <li key={doc.id} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', fontSize: '14px' }}>
                <span style={{ cursor: 'pointer' }}>{doc.title}</span>
                <span style={{ color: '#e67e22', fontWeight: 'bold', fontSize: '12px' }}>{doc.status}</span>
              </li>
            ))}
          </ul>
        </div>

      </div>
    </div>
  );
};

export default DashboardPage;
