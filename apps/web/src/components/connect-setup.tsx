import { ExternalLink } from 'lucide-react';
import { ValueRow } from './ui';

export function ConnectSetup() {
  return <div className="connect-setup">
    <div className="setup-heading"><span>Connect 应用设置</span><a className="text-link" href="https://connect.linux.do" target="_blank" rel="noopener noreferrer">打开 Connect<ExternalLink size={13} /></a></div>
    <dl className="setup-fields">
      <div><dt>应用名称</dt><dd className="muted">自行填写</dd></div>
      <div><dt>应用主页</dt><dd><ValueRow label="应用主页" value={window.location.origin} copy /><span className="muted setup-hint">也可自行填写</span></dd></div>
      <div><dt>应用描述</dt><dd className="muted">自行填写</dd></div>
      <div><dt>LOGO</dt><dd className="muted">按需填写</dd></div>
      <div><dt>最低等级</dt><dd><code>0</code></dd></div>
      <div><dt>回调地址</dt><dd><ValueRow label="Connect 回调地址" value={new URL('/auth/connect/callback', window.location.origin).href} copy /></dd></div>
    </dl>
  </div>;
}
