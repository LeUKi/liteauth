import * as AlertDialog from '@radix-ui/react-alert-dialog';
import * as Dialog from '@radix-ui/react-dialog';
import * as RadixSwitch from '@radix-ui/react-switch';
import { Check, Copy, LoaderCircle, X } from 'lucide-react';
import { m, useReducedMotion } from 'motion/react';
import { useId, useState } from 'react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { errorMessage } from '../lib/api';

export function Button({ className = '', variant = 'primary', busy = false, children, disabled, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; busy?: boolean;
}) {
  return <button {...props} className={`button button-${variant} ${className}`} disabled={disabled || busy} aria-busy={busy || undefined}>
    {busy && <LoaderCircle className="spinner" size={16} aria-hidden="true" />}{children}
  </button>;
}

export function Page({ children, narrow = false }: { children: ReactNode; narrow?: boolean }) {
  const reduced = useReducedMotion();
  return <m.main id="main" className={`page ${narrow ? 'page-narrow' : ''}`} initial={{ opacity: 0, y: reduced ? 0 : 5 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: reduced ? 0 : 0.16 }}>{children}</m.main>;
}

export function PageHeading({ title, action, back }: { title: string; action?: ReactNode; back?: ReactNode }) {
  return <div className="page-heading">{back}<div className="heading-row"><h1>{title}</h1>{action}</div></div>;
}

export function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{children}</section>;
}

export function Notice({ children, kind = 'error' }: { children: ReactNode; kind?: 'error' | 'success' | 'neutral' }) {
  if (!children) return null;
  return <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>;
}

export function Loading({ label = '正在加载' }: { label?: string }) {
  return <div className="loading" role="status"><LoaderCircle size={19} className="spinner" aria-hidden="true" /><span>{label}</span></div>;
}

export function QueryError({ error, retry }: { error: unknown; retry: () => unknown }) {
  return <Panel><div className="empty-state"><Notice>{errorMessage(error)}</Notice><Button variant="secondary" onClick={() => void retry()}>重试</Button></div></Panel>;
}

export function Field({ label, error, children, htmlFor }: { label: string; error?: string; children: ReactNode; htmlFor: string }) {
  return <div className="field"><label htmlFor={htmlFor}>{label}</label>{children}{error && <span className="field-error" id={`${htmlFor}-error`} role="alert">{error}</span>}</div>;
}

export function Switch({ label, checked, onCheckedChange, disabled = false }: { label: string; checked: boolean; onCheckedChange: (checked: boolean) => void; disabled?: boolean }) {
  const id = useId();
  return <div className="setting-row"><label htmlFor={id}>{label}</label><RadixSwitch.Root className="switch" id={id} checked={checked} onCheckedChange={onCheckedChange} disabled={disabled}><RadixSwitch.Thumb className="switch-thumb" /></RadixSwitch.Root></div>;
}

export function CopyButton({ value, label = '复制', children }: { value: string; label?: string; children?: ReactNode }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setFailed(false);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setFailed(true);
    }
  }
  return <span className="copy-control"><Button type="button" variant="ghost" className="button-icon" aria-label={copied ? '已复制' : label} title={copied ? '已复制' : label} onClick={() => void copy()}>{copied ? <Check size={16} /> : <Copy size={16} />}{children}</Button>{failed && <span className="field-error" role="status">请手动复制</span>}</span>;
}

export function ValueRow({ label, value, copy = false }: { label: string; value: string; copy?: boolean }) {
  return <div className="value-row"><span className="value-label">{label}</span><div className="value-content"><code>{value}</code>{copy && <CopyButton value={value} label={`复制${label}`} />}</div></div>;
}

export function SecretValue({ value }: { value: string }) {
  const id = useId();
  return <div className="value-row"><span className="value-label" id={id}>Client Secret</span><div className="secret-value"><code aria-labelledby={id}>{value}</code><CopyButton value={value} label="复制 Client Secret" /></div></div>;
}

export function Modal({ title, description, open, onOpenChange, children, className = '' }: { title: string; description?: string; open: boolean; onOpenChange: (open: boolean) => void; children: ReactNode; className?: string }) {
  return <Dialog.Root open={open} onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className={`dialog-content ${className}`}><div className="dialog-heading"><Dialog.Title>{title}</Dialog.Title><Dialog.Close asChild><Button variant="ghost" className="button-icon" aria-label="关闭"><X size={18} /></Button></Dialog.Close></div>{description ? <Dialog.Description className="dialog-description">{description}</Dialog.Description> : <Dialog.Description className="sr-only">{title}</Dialog.Description>}{children}</Dialog.Content></Dialog.Portal></Dialog.Root>;
}

export function Confirm({ title, description, children, onConfirm, confirmLabel = '确认' }: { title: string; description: string; children: ReactNode; onConfirm: () => Promise<unknown>; confirmLabel?: string }) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function confirm() {
    setPending(true);
    setError(null);
    try {
      await onConfirm();
      setOpen(false);
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return <AlertDialog.Root open={open} onOpenChange={(value) => { if (!pending) { setOpen(value); setError(null); } }}><AlertDialog.Trigger asChild>{children}</AlertDialog.Trigger><AlertDialog.Portal><AlertDialog.Overlay className="dialog-overlay" /><AlertDialog.Content className="dialog-content dialog-small"><AlertDialog.Title className="dialog-title">{title}</AlertDialog.Title><AlertDialog.Description className="dialog-description">{description}</AlertDialog.Description>{error !== null && <Notice>{errorMessage(error)}</Notice>}<div className="form-actions"><AlertDialog.Cancel asChild><Button variant="secondary" disabled={pending}>取消</Button></AlertDialog.Cancel><AlertDialog.Action asChild><Button variant="danger" busy={pending} onClick={(event) => { event.preventDefault(); void confirm(); }}>{confirmLabel}</Button></AlertDialog.Action></div></AlertDialog.Content></AlertDialog.Portal></AlertDialog.Root>;
}

export function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

export function formatRecordDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(date);
}
