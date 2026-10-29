import React, { useState, useEffect } from 'react';
import axios from 'axios';

const EmployeeManage = () => {
  const [employees, setEmployees] = useState([]);
  const [searchTerm, setSearchTerm] = useState(''); // 검색어 상태
  const [editId, setEditId] = useState(null);
  const [editForm, setEditForm] = useState({ phone_number: '', address: '' });

  const fetchEmployees = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/employees/');
      setEmployees(response.data);
    } catch (error) {
      console.error('직원 목록 로드 오류:', error);
    }
  };

  useEffect(() => { fetchEmployees(); }, []);

  const handleEditClick = (emp) => {
    setEditId(emp.employee_id);
    setEditForm({ phone_number: emp.phone_number, address: emp.address });
  };

  const handleSaveClick = async (empId) => {
    try {
      await axios.post('http://127.0.0.1:8000/employees/update/', {
        employee_id: empId,
        ...editForm
      });
      alert('수정되었습니다.');
      setEditId(null);
      fetchEmployees();
    } catch (error) {
      alert('수정 중 오류 발생');
    }
  };

  // 💡 검색 필터링 로직 (사번 또는 이름으로 검색)
  const filteredEmployees = employees.filter(emp => 
    emp.name.includes(searchTerm) || emp.emp_code.includes(searchTerm)
  );

  return (
    <div className="dashboard-container" style={{ maxWidth: '1200px' }}>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 className="page-title">👥 사원 및 권한 관리</h2>
          <p className="page-subtitle">정직원 목록 조회 및 정보 수정 (이름, 사번, 이메일 등 핵심 정보는 불변)</p>
        </div>
        {/* 💡 검색창이 늘어나지 않도록 감싸는 div 추가 및 flex: 'none' 적용 */}
        <div style={{ flexShrink: 0 }}>
          <input 
            type="text" 
            placeholder="🔍 이름 또는 사번 검색..." 
            className="custom-input" 
            style={{ width: '250px', flex: 'none' }} 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="card" style={{ overflowX: 'auto' }}>
        <table className="custom-table" style={{ minWidth: '1000px' }}>
          <thead>
            <tr>
              <th>사번 (발급됨)</th>
              <th>이름</th>
              <th>개인 ID (로그인)</th>
              <th>주민번호</th>
              <th>회사 이메일</th>
              <th>연락처 (수정가능)</th>
              <th>관리</th>
            </tr>
          </thead>
          <tbody>
            {filteredEmployees.length > 0 ? filteredEmployees.map((emp) => (
              <tr key={emp.employee_id}>
                <td><span className="badge badge-green">{emp.emp_code}</span></td>
                <td style={{ fontWeight: 'bold' }}>{emp.name}</td>
                <td style={{ color: '#64748b' }}>{emp.employee_id}</td>
                <td style={{ color: '#64748b' }}>{emp.jumin_no}</td>
                <td>{emp.email}</td>
                <td>
                  {editId === emp.employee_id ? (
                    <input className="custom-input" style={{ padding: '6px', width: '130px' }} value={editForm.phone_number} onChange={(e) => setEditForm({...editForm, phone_number: e.target.value})} />
                  ) : emp.phone_number}
                </td>
                <td>
                  {editId === emp.employee_id ? (
                    <div style={{ display: 'flex', gap: '5px', justifyContent: 'center' }}>
                      <button onClick={() => handleSaveClick(emp.employee_id)} className="badge badge-green" style={{ border: 'none', cursor: 'pointer' }}>저장</button>
                      <button onClick={() => setEditId(null)} className="badge badge-red" style={{ border: 'none', cursor: 'pointer' }}>취소</button>
                    </div>
                  ) : (
                    <button onClick={() => handleEditClick(emp)} className="badge" style={{ backgroundColor: '#e2e8f0', color: '#475569', border: 'none', cursor: 'pointer' }}>수정</button>
                  )}
                </td>
              </tr>
            )) : (
              <tr><td colSpan="7" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>검색된 사원이 없습니다.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default EmployeeManage;