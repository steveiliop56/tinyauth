import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Button } from "../ui/button";

interface Props {
  onClick: () => void;
  appUrl: string;
  currentUrl: string;
}

export const DomainWarning = (props: Props) => {
  const { onClick, appUrl, currentUrl } = props;

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">Incorrect Domain</CardTitle>
        <CardDescription>
          This instance is configured to be accessed from <code>{appUrl}</code>,
          but <code>{currentUrl}</code> is being used. Authentication will most
          likely fail if you proceed.
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button onClick={onClick} variant="warning">
          Continue
        </Button>
      </CardFooter>
    </Card>
  );
};
