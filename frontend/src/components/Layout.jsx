/**
 * @file Layout.jsx
 * @description 사이드바와 상단 헤더를 모든 페이지에 공통으로 제공하는 레이아웃 래퍼(Wrapper)입니다.
 * 이를 통해 각 페이지 코드에서 사이드바 코드를 수백 줄씩 삭제(중복 제거)할 수 있습니다.
 */

import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const Layout = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const currentUser = JSON.parse(sessionStorage.getItem('loggedInUser'));

  if (!currentUser) {
    setTimeout(() => navigate('/login'), 0);
    return null;
  }

  return (
    <div className="board-container" style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* 1. 사이드바 */}
      <aside className="sidebar" style={{ width: '260px', backgroundColor: '#1e293b', color: 'white', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        {/* ★ 회사명 클릭 시 홈페이지(/)로 이동 */}
        <div className="sidebar-header" onClick={() => navigate('/')} style={{ padding: '25px 20px', cursor: 'pointer', borderBottom: '1px solid #334155' }}>
          <h2 style={{ fontSize: '1.4rem', margin: 0, color: '#38bdf8' }}>SecureTech</h2>
          <p style={{ fontSize: '0.85rem', margin: '5px 0 0 0', color: '#94a3b8' }}>Groupware System</p>
        </div>

        <ul className="sidebar-menu" style={{ listStyle: 'none', padding: '20px 0', margin: 0, flex: 1 }}>
          <li className={location.pathname === '/dashboard' ? 'active' : ''} onClick={() => navigate('/dashboard')} style={menuItemStyle(location.pathname === '/dashboard')}>홈 (대시보드)</li>
          <li className={location.pathname === '/notice' ? 'active' : ''} onClick={() => navigate('/notice')} style={menuItemStyle(location.pathname === '/notice')}>공지사항</li>
          <li className={location.pathname === '/board' ? 'active' : ''} onClick={() => navigate('/board')} style={menuItemStyle(location.pathname === '/board')}>사내 게시판</li>
          <li className={location.pathname === '/approval' ? 'active' : ''} onClick={() => navigate('/approval')} style={menuItemStyle(location.pathname === '/approval')}>전자결재</li>
          <li className={location.pathname === '/orgchart' ? 'active' : ''} onClick={() => navigate('/orgchart')} style={menuItemStyle(location.pathname === '/orgchart')}>조직도</li>

          {currentUser.role === '관리자' && (
            <>
              <li style={{ padding: '12px 20px', color: '#64748b', fontSize: '0.8rem', fontWeight: 'bold' }}>[ 관리자 메뉴 ]</li>
              <li className={location.pathname === '/admin/approval' ? 'active' : ''} onClick={() => navigate('/admin/approval')} style={menuItemStyle(location.pathname === '/admin/approval')}>인사/계정 관리</li>
              <li className={location.pathname === '/admin/assets' ? 'active' : ''} onClick={() => navigate('/admin/assets')} style={menuItemStyle(location.pathname === '/admin/assets')}>IT 자산/IP 관리</li>
              <li className={location.pathname === '/firewall' ? 'active' : ''} onClick={() => navigate('/firewall')} style={menuItemStyle(location.pathname === '/firewall')}>방화벽 정책 관리</li>
            </>
          )}
        </ul>
      </aside>

      {/* 2. 우측 메인 영역 */}
      <main className="board-main" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', backgroundColor: '#f8fafc' }}>
        {/* 상단 헤더 */}
        <header className="board-header" style={{ height: '70px', backgroundColor: 'white', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 30px', flexShrink: 0 }}>
          {/* ★ 상단 헤더 클릭 시 홈페이지(/)로 이동 & 인트라넷 -> 그룹웨어 변경 */}
          <h2 onClick={() => navigate('/')} style={{ fontSize: '1.2rem', color: '#1e293b', margin: 0, cursor: 'pointer' }}>
            SecureTech 그룹웨어
          </h2>
          <div className="user-info" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            {currentUser.role === '관리자' && (
              <button
                onClick={() => navigate('/security')}
                style={{ backgroundColor: '#0f172a', color: '#38bdf8', border: '1px solid #38bdf8', padding: '7px 14px', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', fontSize: '0.85rem' }}>
                🛡️ SOC 관제 모드
              </button>
            )}
            <span onClick={() => navigate('/mypage')} style={{ cursor: 'pointer', color: '#2563eb', fontWeight: 'bold', fontSize: '0.95rem' }} title="마이페이지로 이동">
              {currentUser.name} 님 ({currentUser.department})
            </span>
            <button onClick={() => { sessionStorage.removeItem('loggedInUser'); navigate('/login'); }} style={{ padding: '6px 12px', backgroundColor: '#ef4444', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 'bold' }}>
              로그아웃
            </button>
          </div>
        </header>

        <section className="board-content" style={{ flex: 1, padding: '30px', overflowY: 'auto' }}>
          {children}
        </section>
      </main>
    </div>
  );
};

const menuItemStyle = (isActive) => ({
  padding: '12px 25px', cursor: 'pointer', color: isActive ? '#38bdf8' : '#cbd5e1', backgroundColor: isActive ? '#334155' : 'transparent',
  fontWeight: isActive ? 'bold' : 'normal', fontSize: '0.95rem', borderLeft: isActive ? '4px solid #38bdf8' : '4px solid transparent', transition: 'all 0.2s'
});

export default Layout;