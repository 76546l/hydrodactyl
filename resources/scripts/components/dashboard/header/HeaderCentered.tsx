import { cn } from '@/lib/utils';

const HeaderCentered = ({ children, className = '' }) => {
    return <div className={cn('flex w-full items-center shrink-0', className)}>{children}</div>;
};

export default HeaderCentered;
