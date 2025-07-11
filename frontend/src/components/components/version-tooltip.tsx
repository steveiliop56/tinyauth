import { useAppContext } from "@/context/app-context";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export const VersionTooltip = () => {
  const { version, buildTimestamp, commitHash } = useAppContext();

  return (
    <Tooltip>
      <TooltipTrigger className="absolute bottom-2 text-muted-foreground text-sm">
        Tinyauth {version}
      </TooltipTrigger>
      <TooltipContent>
        <p>Version: {version}</p>
        <p>Build Timestamp: {buildTimestamp}</p>
        <p>Commit Hash: {commitHash}</p>
      </TooltipContent>
    </Tooltip>
  );
};
