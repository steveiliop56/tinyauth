import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";

export const ErrorPage = () => {
  const { t } = useTranslation();
  const { search } = useLocation();
  const searchParams = new URLSearchParams(search);
  const error = searchParams.get("error") ?? "";

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("errorTitle")}</CardTitle>
        <CardDescription className="flex flex-col gap-1.5">
          {error ? (
            <>
              <p>The following error occured while processing your request:</p>
              <pre>{error}</pre>
            </>
          ) : (
            <>
              <p>{t("errorSubtitle")}</p>
            </>
          )}
        </CardDescription>
      </CardHeader>
    </Card>
  );
};
