import { Loader2 } from "lucide-react";
import { Button } from "../ui/button";
import React from "react";

interface Props {
  title: string;
  icon: React.ReactNode;
  onClick?: () => void;
  loading?: boolean;
}

export const OAuthButton = (props: Props) => {
  const { title, icon, onClick, loading } = props;

  return (
    <Button
      onClick={onClick}
      className="rounded-full basis-1/3"
      variant="outline"
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
