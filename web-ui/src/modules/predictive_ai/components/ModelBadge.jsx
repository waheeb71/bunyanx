export function ModelBadge({ status }) {
  if (status === 'Loaded')
    return <span className="pai-model-badge pai-model-badge--ok">● مُحمّل</span>;
  if (status?.includes('Waiting'))
    return <span className="pai-model-badge pai-model-badge--wait">○ انتظار</span>;
  return <span className="pai-model-badge pai-model-badge--err">{status}</span>;
}

export default ModelBadge;
