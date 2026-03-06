import { useCallback, useEffect, useState } from 'react';

import type { AppPage } from '../navigation';
import { getPageFromPathname, pageToPath } from '../navigation';

export function useAppNavigation(): {
  currentPage: AppPage;
  navigateTo: (page: AppPage) => void;
} {
  const [currentPage, setCurrentPage] = useState<AppPage>(() =>
    getPageFromPathname(window.location.pathname),
  );

  const navigateTo = useCallback((page: AppPage) => {
    setCurrentPage(page);
    window.history.pushState({ page }, '', pageToPath(page));
  }, []);

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPage(getPageFromPathname(window.location.pathname));
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  return { currentPage, navigateTo };
}
