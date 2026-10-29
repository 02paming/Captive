/**
 * @file MainPage.jsx
 * @description 로그인 전 접속할 수 있는 사외용 메인(랜딩) 페이지입니다.
 * 인트라넷(그룹웨어)으로 넘어갈 수 있는 진입점 역할을 합니다.
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './MainPage.css';

const MainPage = () => {
  const navigate = useNavigate();

  // ★ 세션에서 로그인된 유저 정보 가져오기 (로그아웃 방지)
  const [currentUser, setCurrentUser] = useState(null);

  useEffect(() => {
    const user = JSON.parse(sessionStorage.getItem('loggedInUser'));
    if (user) setCurrentUser(user);
  }, []);

  const handleLogout = () => {
    sessionStorage.removeItem('loggedInUser');
    setCurrentUser(null);
    alert('로그아웃 되었습니다.');
  };

  // ★ 관리자 전용 홈페이지 내용 수정 상태(State)
  const [isEditing, setIsEditing] = useState(false);
  const [pageContent, setPageContent] = useState({
    title: '안전한 연결, 혁신적인 업무 환경',
    subtitle: 'SecureTech는 강력한 네트워크 보안(SOC)과 스마트한 그룹웨어를 통합 제공하는 차세대 플랫폼입니다.'
  });

  return (
    <div className="pr-main-container">
      {/* 1. 상단 네비게이션 바 */}
      <nav className="pr-navbar">
        <div className="pr-logo">SecureTech</div>
        <div className="pr-nav-links">
          {currentUser ? (
            // [로그인 상태일 때 보여줄 버튼들]
            <>
              {currentUser.role === '관리자' && (
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className={`pr-nav-btn ${isEditing ? 'save-btn' : 'edit-btn'}`}
                >
                  {isEditing ? '💾 변경사항 저장' : '⚙️ 홈페이지 편집'}
                </button>
              )}
              <button onClick={() => navigate('/dashboard')} className="pr-nav-btn dashboard-btn">그룹웨어로 돌아가기</button>
              <button onClick={handleLogout} className="pr-nav-btn logout-btn">로그아웃</button>
            </>
          ) : (
            // [비로그인 상태일 때 보여줄 버튼들]
            <>
              <button onClick={() => navigate('/login')} className="pr-nav-btn login-btn">그룹웨어 로그인</button>
              <button onClick={() => navigate('/signup')} className="pr-nav-btn signup-btn">입사 지원 (계정 신청)</button>
            </>
          )}
        </div>
      </nav>

      {/* 2. 메인 홍보(히어로) 섹션 */}
      <header className="pr-hero-section">
        <div className="pr-hero-content">
          {isEditing ? (
            // ★ 편집 모드 켜졌을 때 (관리자 전용 입력창)
            <div className="edit-mode-box">
              <input
                type="text"
                value={pageContent.title}
                onChange={(e) => setPageContent({ ...pageContent, title: e.target.value })}
                className="edit-input-title"
              />
              <textarea
                value={pageContent.subtitle}
                onChange={(e) => setPageContent({ ...pageContent, subtitle: e.target.value })}
                className="edit-input-subtitle"
              />
            </div>
          ) : (
            // 일반 뷰 모드
            <>
              <h1>{pageContent.title}</h1>
              <p>{pageContent.subtitle}</p>
            </>
          )}

          <button onClick={() => navigate(currentUser ? '/dashboard' : '/login')} className="pr-hero-action-btn">
            {currentUser ? '내 대시보드로 이동' : '솔루션 시작하기'}
          </button>
        </div>
      </header>

      {/* 3. 핵심 서비스 소개 섹션 */}
      <section className="pr-services-section">
        <div className="pr-service-card">
          <div className="service-icon">🛡️</div>
          <h3>실시간 SOC 관제</h3>
          <p>libpcap 및 iptables 기반의 강력한 사내망 패킷 모니터링과 악성 IP 자동 차단 시스템을 제공합니다.</p>
        </div>
        <div className="pr-service-card">
          <div className="service-icon">🏢</div>
          <h3>스마트 그룹웨어</h3>
          <p>전자결재, 사내 게시판, 조직도 등 기업 운영과 소통에 필요한 모든 기능을 하나의 플랫폼에 담았습니다.</p>
        </div>
        <div className="pr-service-card">
          <div className="service-icon">💻</div>
          <h3>IT 자산/IP 관리</h3>
          <p>사내 네트워크에 연결된 모든 하드웨어 기기와 할당된 IP 주소를 중앙에서 효율적으로 통제합니다.</p>
        </div>
      </section>

      {/* 4. 푸터 */}
      <footer className="pr-footer">
        <p>© 2026 SecureTech Inc. All rights reserved. | 보안개발실 인트라넷 프로젝트</p>
      </footer>
    </div>
  );
};

export default MainPage;
