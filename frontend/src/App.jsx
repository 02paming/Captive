import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import PolicyManage from './pages/PolicyManage';
import EmployeeManage from './pages/EmployeeManage';
import SignupApproval from './pages/SignupApproval';
import MyPage from './pages/MyPage';
import Home from './pages/Home';
import Login from './pages/Login';
import Signup from './pages/Signup';
import './App.css';

function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const loggedInUser = localStorage.getItem('user');
    if (loggedInUser) {
      setUser(JSON.parse(loggedInUser));
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('user');
    setUser(null);
    window.location.href = '/home'; // 💡 로그아웃 시에도 홈페이지(Home)로 이동
  };

  return (
    <Router>
      <div>
        <nav className="navbar">
          <div className="nav-brand">
            {/* 💡 로고 클릭 시 무조건 /home (최초 홍보 페이지)으로 이동 */}
            <Link to="/home" style={{ color: 'white', textDecoration: 'none' }}>🛡 SecureTech</Link>
          </div>
          
          {user ? (
            <>
              <div className="nav-links">
                {/* 💡 로그인한 유저의 대시보드 주소는 '/' 로 유지 */}
                <Link to="/" className="nav-link">대시보드</Link>
                <Link to="/policy" className="nav-link">정책 관리</Link>
                
                {user.is_manager && (
                  <>
                    <Link to="/employees" className="nav-link">사원 관리</Link>
                    <Link to="/approvals" className="nav-link">가입 승인</Link>
                  </>
                )}
              </div>
              <div className="user-info">
                <Link to="/mypage" style={{ textDecoration: 'none' }}>
                  <span className="user-greeting" style={{ cursor: 'pointer' }}>🧑‍💻 <b>{user.name}</b>님 접속 중</span>
                </Link>
                <button onClick={handleLogout} className="btn-logout">로그아웃</button>
              </div>
            </>
          ) : (
            <div className="user-info">
              <Link to="/login" className="btn-login" style={{ textDecoration: 'none' }}>로그인</Link>
            </div>
          )}
        </nav>

        <div style={{ padding: '40px 20px' }}>
          <Routes>
            {/* 💡 주소가 '/' 일 때: 로그인했으면 대시보드, 안 했으면 홈 */}
            <Route path="/" element={user ? <Dashboard /> : <Home />} />
            
            {/* 💡 명시적으로 /home 주소를 만들어 홈 페이지 연결 */}
            <Route path="/home" element={<Home />} />
            
            <Route path="/login" element={<Login />} />
            <Route path="/signup" element={<Signup />} />
            
            {user && (
              <>
                <Route path="/policy" element={<PolicyManage />} />
                <Route path="/mypage" element={<MyPage />} />
                
                {user.is_manager && (
                  <>
                    <Route path="/employees" element={<EmployeeManage />} />
                    <Route path="/approvals" element={<SignupApproval />} />
                  </>
                )}
              </>
            )}

            {/* 비정상적인 경로 접근 시 */}
            <Route path="*" element={user ? <Dashboard /> : <Home />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;
