import React from 'react';
import { motion } from 'framer-motion';
import { Sparkles, ShieldCheck, AlertTriangle, ArrowRight, Zap, CheckCircle2, ChevronLeft } from 'lucide-react';

export default function ExecutiveInsightsPanel({
  securityScore = 88,
  activeIncidents = [],
  blockRate = 99.4,
  modulesState = {},
}) {
  // Generate strategic dynamic recommendations based on live state
  const insights = [
    {
      id: 'ins-1',
      title: 'تحصين قواعد WAF الذكية (GNN)',
      category: 'استباقي',
      level: 'high',
      levelLabel: 'أولوية عليا',
      color: '#ffab40',
      description: 'تم رصد زيادة في محاولات الحقن المتقدمة. يُوصى بتفعيل سياسة الفحص العميق لمسارات الـ API الحساسة.',
      impact: '+4.2% تعزيز درجة الأمان',
    },
    {
      id: 'ins-2',
      title: 'سياسة منع تسريب البيانات (DLP Policy)',
      category: 'بيانات',
      level: 'medium',
      levelLabel: 'أولوية متوسطة',
      color: '#00c8ff',
      description: 'تطبيق التشفير التلقائي وفحص البصمات الرقمية للمستندات الصادرة عبر قنوات البريد والويب.',
      impact: 'امتثال كامل للمعيار الوطني',
    },
    {
      id: 'ins-3',
      title: 'كفاءة الاستجابة التلقائية للتهديدات',
      category: 'تشغيلي',
      level: 'low',
      levelLabel: 'تحسين مستمر',
      color: '#00e676',
      description: 'معدل الحظر الفوري للتهديدات مستقر عند ' + blockRate + '%. المنظومة تعمل بأعلى كفاءة اعتراض.',
      impact: '0 ثغرات نشطة غير محتواة',
    },
  ];

  return (
    <motion.div
      className="exec-panel exec-insights-panel"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.3 }}
    >
      <div className="exec-panel-header">
        <div className="exec-panel-title-group">
          <div className="exec-panel-icon-wrap" style={{ background: 'rgba(129, 140, 248, 0.15)', color: '#818cf8' }}>
            <Sparkles size={18} />
          </div>
          <div>
            <h3 className="exec-panel-title">تحليلات وتوصيات الذكاء الاصطناعي الاستراتيجية</h3>
            <span className="exec-panel-sub">رؤى موجهة للقيادة التنفيذية لدعم اتخاذ القرارات الأمنية</span>
          </div>
        </div>
        <div className="exec-insights-badge">
          <Zap size={13} />
          تحليل استباقي لحظي
        </div>
      </div>

      <div className="exec-insights-list">
        {insights.map((item, idx) => (
          <div key={item.id} className="exec-insight-card">
            <div className="exec-insight-header">
              <div className="exec-insight-title-group">
                <span className="exec-insight-dot" style={{ background: item.color, boxShadow: `0 0 8px ${item.color}88` }} />
                <span className="exec-insight-title">{item.title}</span>
              </div>
              <span
                className="exec-insight-level-tag"
                style={{
                  color: item.color,
                  background: `${item.color}15`,
                  borderColor: `${item.color}33`,
                }}
              >
                {item.levelLabel}
              </span>
            </div>

            <p className="exec-insight-desc">{item.description}</p>

            <div className="exec-insight-footer">
              <div className="exec-insight-impact">
                <CheckCircle2 size={13} style={{ color: '#00e676' }} />
                <span>{item.impact}</span>
              </div>
              <span className="exec-insight-category-chip">{item.category}</span>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
