/**
 * Brand lockup: the SVG mark (public/logo-mark.svg) plus the name as real text,
 * so it stays crisp, themeable and readable by screen readers.
 * size: 'md' (default) | 'lg'. stacked puts the name under the mark.
 */
export default function Logo({ size = 'md', stacked = false, showName = true }) {
  const cls = ['logo', size === 'lg' && 'logo--lg', stacked && 'logo--stacked'].filter(Boolean).join(' ');
  return (
    <span className={cls}>
      <img className="logo__mark" src="/logo-mark.svg" alt={showName ? '' : 'Access Vault'} />
      {showName && <span>Access Vault</span>}
    </span>
  );
}
