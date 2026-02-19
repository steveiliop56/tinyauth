import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Button } from "../ui/button";
import { Trans, useTranslation } from "react-i18next";
import { useLocation } from "react-router";

interface Props {
  onClick: () => void;
  appUrl: string;
  currentUrl: string;
}

export const DomainWarning = (props: Props) => {
  const { onClick, appUrl, currentUrl } = props;
  const { t } = useTranslation();
  const { search } = useLocation();

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri");

  return (
    <Card role="alert" aria-live="assertive" className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("domainWarningTitle")}</CardTitle>
        <CardDescription>
          <Trans
            t={t}
            i18nKey="domainWarningSubtitle"
            values={{ appUrl, currentUrl }}
            components={{ code: <code /> }}
            shouldUnescape={true}
          />
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch gap-2">
        <Button onClick={onClick} variant="warning">
          {t("ignoreTitle")}
        </Button>
        <Button
          onClick={() =>
            window.location.assign(
              `${appUrl}/login?redirect_uri=${encodeURIComponent(redirectUri || "")}`,
            )
          }
          variant="outline"
        >
          {t("goToCorrectDomainTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};
