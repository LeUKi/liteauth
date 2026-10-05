import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { LazyMotion, MotionConfig } from 'motion/react';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ApiFailure } from './lib/api';
import { router } from './router';
import { SiteFooter } from './components/layout';
import './styles.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (attempt, error) => attempt < 1 && (!(error instanceof ApiFailure) || error.status >= 500),
      refetchOnWindowFocus: true,
      staleTime: 10_000,
    },
    mutations: { retry: false },
  },
});

const loadMotionFeatures = () => import('./lib/motion-features').then((module) => module.default);

createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={queryClient}><MotionConfig reducedMotion="user"><LazyMotion features={loadMotionFeatures} strict><div className="app-shell"><RouterProvider router={router} /><SiteFooter /></div></LazyMotion></MotionConfig></QueryClientProvider></StrictMode>);
