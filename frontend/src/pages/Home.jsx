import React from 'react';
import { Link } from 'react-router-dom';

const Home = () => {
  return (
    <div style={{ textAlign: 'center', marginTop: '80px', padding: '0 20px' }}>
      <div style={{ display: 'inline-block', padding: '10px 20px', backgroundColor: '#e0f2fe', color: '#0369a1', borderRadius: '20px', fontWeight: 'bold', marginBottom: '20px' }}>
        Next-Gen Security Platform
      </div>
      <h1 style={{ fontSize: '48px', color: '#0f172a', fontWeight: '800', marginBottom: '20px', letterSpacing: '-1px' }}>
        기업의 자산을 완벽하게 보호하는 <br /> 
        <span style={{ color: '#38bdf8' }}>SecureTech</span> 중앙 관제 시스템
      </h1>
      <p style={{ fontSize: '18px', color: '#64748b', lineHeight: '1.6', marginBottom: '40px', maxWidth: '600px', margin: '0 auto 40px auto' }}>
        실시간 패킷 분석 엔진(PCAP)과 연동된 지능형 인트라넷을 통해<br />
        사내망 접근 제어와 위협 탐지를 하나의 대시보드에서 완벽하게 통제하세요.
      </p>
      
      <div style={{ display: 'flex', justifyContent: 'center', gap: '20px' }}>
        <Link to="/login" className="btn-primary" style={{ textDecoration: 'none', padding: '16px 40px', fontSize: '16px', borderRadius: '30px' }}>
          시스템 로그인
        </Link>
        <Link to="/signup" className="btn-primary" style={{ textDecoration: 'none', backgroundColor: '#f1f5f9', color: '#334155', padding: '16px 40px', fontSize: '16px', borderRadius: '30px' }}>
          사원 가입 신청
        </Link>
      </div>

      <div style={{ marginTop: '80px', display: 'flex', justifyContent: 'center', gap: '50px', color: '#475569' }}>
        <div>
          <h3 style={{ fontSize: '24px', marginBottom: '10px' }}>🛡️</h3>
          <p style={{ fontWeight: 'bold' }}>실시간 위협 차단</p>
        </div>
        <div>
          <h3 style={{ fontSize: '24px', marginBottom: '10px' }}>📊</h3>
          <p style={{ fontWeight: 'bold' }}>직관적 대시보드</p>
        </div>
        <div>
          <h3 style={{ fontSize: '24px', marginBottom: '10px' }}>🧑‍💻</h3>
          <p style={{ fontWeight: 'bold' }}>통합 인사 연동</p>
        </div>
      </div>
    </div>
  );
};

export default Home;