export default function Toggle({ checked, onChange }) {
  return (
    <label className="prx-toggle">
      <input type="checkbox" checked={!!checked} onChange={onChange} />
      <span className="prx-toggle-slider" />
    </label>
  );
}
