import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const Signup = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    member_id: '', password: '', name: '', email: '', 
    phone_number: '', jumin_no: '', address: ''
  });

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  // 💡 [핵심] 개별 필드 중복 검사 함수
  const checkDuplicate = async (field, value) => {
    try {
      const response = await axios.post('http://127.0.0.1:8000/auth/check-duplicate/', {
        field: field,
        value: value
      });
      return response.data; // { is_duplicate: true/false, message: "..." }
    } catch (error) {
      console.error("중복 검사 중 오류:", error);
      return { is_duplicate: false }; // 통신 오류 시 일단 통과시키고 DB에서 거르도록 함
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    
    // 하이픈 제거 데이터 준비
    const cleanPhoneNumber = formData.phone_number.replace(/-/g, '');
    const cleanJuminNo = formData.jumin_no.replace(/-/g, '');

    // 💡 1. 아이디 중복 검사
    const idCheck = await checkDuplicate('member_id', formData.member_id);
    if (idCheck.is_duplicate) { alert(idCheck.message); return; }

    // 💡 2. 이메일 중복 검사
    const emailCheck = await checkDuplicate('email', formData.email);
    if (emailCheck.is_duplicate) { alert(emailCheck.message); return; }

    // 💡 3. 전화번호 중복 검사
    const phoneCheck = await checkDuplicate('phone_number', cleanPhoneNumber);
    if (phoneCheck.is_duplicate) { alert(phoneCheck.message); return; }

    // 💡 4. 주민번호 중복 검사
    const juminCheck = await checkDuplicate('jumin_no', cleanJuminNo);
    if (juminCheck.is_duplicate) { alert(juminCheck.message); return; }


    // 모든 중복 검사를 통과했다면 실제 가입 요청 진행
    try {
      const submitData = { 
        member_id: formData.member_id, 
        password: formData.password,
        name: formData.name,
        email: formData.email,
        address: formData.address,
        phone_number: cleanPhoneNumber,
        jumin_no: cleanJuminNo
      };

      const response = await axios.post('http://127.0.0.1:8000/auth/apply/', submitData);
      
      if (response.status === 201) {
        alert('가입 신청이 완료되었습니다! 관리자 승인을 대기해주세요.');
        navigate('/login');
      }
    } catch (error) {
      alert('가입 신청 중 서버 오류가 발생했습니다.');
    }
  };

  return (
    <div style={{ padding: '30px', maxWidth: '500px', margin: '0 auto' }}>
      <h2 style={{ textAlign: 'center' }}>📝 사원 가입 신청</h2>
      <form onSubmit={handleSignup} style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '20px' }}>
        <input name="member_id" placeholder="희망 아이디 (로그인용)" onChange={handleChange} required style={{ padding: '10px' }} />
        <input name="password" type="password" placeholder="비밀번호" onChange={handleChange} required style={{ padding: '10px' }} />
        <input name="name" placeholder="이름 (동명이인 허용)" onChange={handleChange} required style={{ padding: '10px' }} />
        <input name="email" type="email" placeholder="개인 이메일" onChange={handleChange} required style={{ padding: '10px' }} />
        <input name="phone_number" placeholder="전화번호 (예: 010-1234-5678)" onChange={handleChange} required style={{ padding: '10px' }} />
        <input name="jumin_no" placeholder="주민번호 앞/뒷자리 (예: 900101-1234567)" onChange={handleChange} required style={{ padding: '10px' }} />
        <input name="address" placeholder="주소" onChange={handleChange} required style={{ padding: '10px' }} />
        
        <button type="submit" style={{ padding: '12px', marginTop: '10px', backgroundColor: '#28a745', color: 'white', border: 'none', borderRadius: '5px', cursor: 'pointer' }}>
          가입 신청하기
        </button>
        <button type="button" onClick={() => navigate('/login')} style={{ padding: '12px', backgroundColor: '#6c757d', color: 'white', border: 'none', borderRadius: '5px', cursor: 'pointer' }}>
          취소하고 돌아가기
        </button>
      </form>
    </div>
  );
};

export default Signup;