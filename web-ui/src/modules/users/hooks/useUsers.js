import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { usersApi } from '../api/usersApi';

export function useUsers() {
  const qc = useQueryClient();
  const [selectedUser, setSelectedUser] = useState(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'viewer' });
  const [newRule, setNewRule] = useState({ resource: 'firewall' });
  const [errorMessage, setErrorMessage] = useState(null);

  /* ── Queries ── */
  const { data: users = [], isLoading, error: usersError } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list().then(r => r.data)
  });

  const { data: rules = [], isLoading: isLoadingRules } = useQuery({
    queryKey: ['user-rules', selectedUser],
    queryFn: () => usersApi.rules(selectedUser).then(r => r.data),
    enabled: !!selectedUser,
  });

  /* ── Mutations ── */
  const createMut = useMutation({
    mutationFn: (data) => usersApi.create(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] });
      setShowAddForm(false);
      setNewUser({ username: '', password: '', role: 'viewer' });
      setErrorMessage(null);
    },
    onError: (err) => {
      setErrorMessage(err.response?.data?.detail || 'فشلت عملية إنشاء المستخدم');
    }
  });

  const deleteMut = useMutation({
    mutationFn: (username) => usersApi.delete(username),
    onSuccess: (_, username) => {
      qc.invalidateQueries({ queryKey: ['users'] });
      if (selectedUser === username) setSelectedUser(null);
      setErrorMessage(null);
    },
    onError: (err) => {
      setErrorMessage(err.response?.data?.detail || 'فشلت عملية حذف المستخدم');
    }
  });

  const addRuleMut = useMutation({
    mutationFn: (data) => usersApi.addRule(selectedUser, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['user-rules', selectedUser] });
      setShowRuleForm(false);
      setErrorMessage(null);
    },
    onError: (err) => {
      setErrorMessage(err.response?.data?.detail || 'فشلت عملية إضافة الصلاحية');
    }
  });

  const deleteRuleMut = useMutation({
    mutationFn: (id) => usersApi.deleteRule(selectedUser, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['user-rules', selectedUser] });
      setErrorMessage(null);
    },
    onError: (err) => {
      setErrorMessage(err.response?.data?.detail || 'فشلت عملية حذف الصلاحية');
    }
  });

  const selectedMeta = users.find(u => u.username === selectedUser);

  return {
    users,
    isLoading,
    usersError,
    rules,
    isLoadingRules,
    selectedUser,
    setSelectedUser,
    selectedMeta,
    showAddForm,
    setShowAddForm,
    showRuleForm,
    setShowRuleForm,
    newUser,
    setNewUser,
    newRule,
    setNewRule,
    errorMessage,
    setErrorMessage,
    onCreateUser: (data) => createMut.mutate(data),
    isCreating: createMut.isPending,
    onDeleteUser: (name) => deleteMut.mutate(name),
    isDeleting: deleteMut.isPending,
    onAddRule: (data) => addRuleMut.mutate(data),
    isAddingRule: addRuleMut.isPending,
    onDeleteRule: (id) => deleteRuleMut.mutate(id),
    isDeletingRule: deleteRuleMut.isPending,
  };
}

export default useUsers;
