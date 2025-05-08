import { Loader2 } from "lucide-react";
import { Button } from "./button";
import React from "react";
import { twMerge } from "tailwind-merge";

interface Props extends React.ComponentProps<typeof Button> {
  title: string;
  icon: React.ReactNode;
  onClick?: () => void;
  loading?: boolean;
}

export const OAuthButton = (props: Props) => {
  const { title, icon, onClick, loading, className, ...rest } = props;

  return (
    <Button
      onClick={onClick}
      className={twMerge("rounded-full", className)}
      variant="outline"
      {...rest}
    >
      {loading ? (
        <Loader2 className="animate-spin" />
      ) : (
        <>
          {icon}
          {title}
        </>
      )}
    </Button>
  );
};
