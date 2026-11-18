import React from 'react';

export function FeedbackSelector({ sampleId, feedbackMutation }) {
  const handleChange = (e) => {
    const val = e.target.value;
    if (val === '') return;
    const label = Number(val);
    const isCorrect = (label !== 0);
    
    feedbackMutation.mutate({ sampleId, label, isCorrect });
    e.target.value = '';
  };

  return (
    <select
      onChange={handleChange}
      defaultValue=""
      title="أرسل تغذية راجعة لتدريب الذكاء الاصطناعي"
      disabled={feedbackMutation?.isPending}
      style={{
        background: 'rgba(255, 255, 255, 0.05)',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        borderRadius: '6px',
        color: 'var(--text-muted)',
        fontSize: '0.74rem',
        padding: '3px 8px',
        cursor: 'pointer',
        outline: 'none',
        fontFamily: 'var(--font-sans)',
      }}
    >
      <option value="" disabled>🧠 تقييم</option>
      <option value="0">❌ خطأ (سليم Benign)</option>
      <option value="5">✅ صحيح (C2 Beacon)</option>
      <option value="6">✅ صحيح (Lateral)</option>
      <option value="9">✅ صحيح (APT)</option>
    </select>
  );
}

export default FeedbackSelector;

