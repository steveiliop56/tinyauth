import { twMerge } from "tailwind-merge";

interface CodeProps extends React.ComponentPropsWithoutRef<"code"> {
  children?: React.ReactNode;
  className?: string;
}

function Code({ children, className, ...props }: CodeProps) {
  return (
    <code
      className={twMerge(
        "relative rounded bg-muted px-[0.2rem] py-[0.1rem] font-mono text-sm font-semibold",
        className,
      )}
      {...props}
    >
      {children}
    </code>
  );
}

export { Code };
