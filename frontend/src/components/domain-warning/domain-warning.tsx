import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Button } from "../ui/button";
import { Trans, useTranslation } from "react-i18next";

interface Props {
  onClick: () => void;
  appUrl: string;
  currentUrl: string;
}

export const DomainWarning = (props: Props) => {
  const { onClick, appUrl, currentUrl } = props;
  const { t } = useTranslation();

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("domainWarningTitle")}</CardTitle>
        <CardDescription>
          <Trans
            t={t}
            i18nKey="domainWarningSubtitle"
            values={{ appUrl, currentUrl }}
            components={{ code: <code /> }}
          />
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button onClick={onClick} variant="warning">
          {t("ignoreTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};
