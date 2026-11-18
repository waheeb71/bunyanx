/**
 * Enterprise PKI & Certificate Lifecycle Manager
 * Full X.509 certificate management, CSR generation, Root CA trust store, state persistence, and SOC UX.
 */
import { useState } from 'react';
import { Key } from 'lucide-react';
import { PageHeader, SectionCard } from '../../components/Shared';
import { usePKI } from './hooks/usePKI';
import { PKIToolbar } from './components/PKIToolbar';
import { PKIKpiCards } from './components/PKIKpiCards';
import { PKICertificateTable } from './components/PKICertificateTable';
import { PKICertificateDetail } from './components/PKICertificateDetail';
import { PKICSRModal } from './components/PKICSRModal';
import { PKICAModal } from './components/PKICAModal';
import './PKIManager.css';

export default function PKIManager() {
  const [showCSR, setShowCSR] = useState(false);
  const [showCA, setShowCA] = useState(false);

  const {
    certs,
    rawCerts,
    selectedCert,
    isLoading,
    isRefetching,
    error,
    refetch,
    caInfo,
    isCaLoading,
    generateDeviceMutation,
    renewMutation,
    revokeMutation,
    generateCaMutation,
    downloadCa,
    daysUntil,
  } = usePKI();

  const handleGenerateCSR = (formData) => {
    generateDeviceMutation.mutate(formData, {
      onSuccess: () => setShowCSR(false),
    });
  };

  return (
    <div className="pki-wrap" dir="rtl">
      {/* Page Header */}
      <PageHeader
        icon={Key}
        title="إدارة البنية التحتية للمفاتيح العمومية (PKI & Certificates)"
        subtitle="مراقبة دورة حياة الشهادات الرقمية X.509، إصدار شهادات الأجهزة، وإدارة سلطة التصديق الرئيسية (Root CA)"
      />

      {/* KPI Cards */}
      <PKIKpiCards
        certs={rawCerts}
        isLoading={isLoading}
        caInfo={caInfo}
        daysUntil={daysUntil}
      />

      {/* Toolbar Controls */}
      <PKIToolbar
        onOpenCSR={() => setShowCSR(true)}
        onOpenCA={() => setShowCA(true)}
        onRefresh={refetch}
        isRefetching={isRefetching}
      />

      {/* Main Certificate Inventory Table */}
      <SectionCard title="مخزن الشهادات الرقمية (Certificates Store)" icon={Key}>
        <PKICertificateTable
          certs={certs}
          isLoading={isLoading}
          error={error}
          onRetry={refetch}
          onRenew={(id) => renewMutation.mutate(id)}
          onRevoke={(id) => revokeMutation.mutate(id)}
          renewingId={renewMutation.variables}
          revokingId={revokeMutation.variables}
          daysUntil={daysUntil}
        />
      </SectionCard>

      {/* Selected Certificate Detail Drawer */}
      {selectedCert && (
        <PKICertificateDetail
          cert={selectedCert}
          daysUntil={daysUntil}
          onRenew={(id) => renewMutation.mutate(id)}
          onRevoke={(id) => revokeMutation.mutate(id)}
          renewingId={renewMutation.variables}
          revokingId={revokeMutation.variables}
        />
      )}

      {/* Device Certificate (CSR) Modal */}
      {showCSR && (
        <PKICSRModal
          onClose={() => setShowCSR(false)}
          onSubmit={handleGenerateCSR}
          isLoading={generateDeviceMutation.isLoading}
        />
      )}

      {/* Root CA Modal */}
      {showCA && (
        <PKICAModal
          onClose={() => setShowCA(false)}
          caInfo={caInfo}
          isCaLoading={isCaLoading}
          onGenerateCa={() => generateCaMutation.mutate()}
          isGeneratingCa={generateCaMutation.isLoading}
          onDownloadCa={downloadCa}
        />
      )}
    </div>
  );
}
