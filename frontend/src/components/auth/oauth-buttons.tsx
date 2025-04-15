import { Grid, Button } from "@mantine/core";
import { GithubIcon } from "../../icons/github";
import { GoogleIcon } from "../../icons/google";
import { OAuthIcon } from "../../icons/oauth";

interface OAuthButtonsProps {
  oauthProviders: string[];
  isPending: boolean;
  mutate: (provider: string) => void;
  genericName: string;
}

export const OAuthButtons = (props: OAuthButtonsProps) => {
  const { oauthProviders, isPending, genericName, mutate } = props;
  return (
    <Grid mb="md" mt="md" align="center" justify="center">
      {oauthProviders.includes("google") && (
        <Grid.Col span="content">
          <Button
            radius="xl"
            leftSection={<GoogleIcon style={{ width: 14, height: 14 }} />}
            variant="default"
            onClick={() => mutate("google")}
            loading={isPending}
          >
            Google
          </Button>
        </Grid.Col>
      )}
      {oauthProviders.includes("github") && (
        <Grid.Col span="content">
          <Button
            radius="xl"
            leftSection={<GithubIcon style={{ width: 14, height: 14 }} />}
            variant="default"
            onClick={() => mutate("github")}
            loading={isPending}
          >
            Github
          </Button>
        </Grid.Col>
      )}
      {oauthProviders.includes("generic") && (
        <Grid.Col span="content">
          <Button
            radius="xl"
            leftSection={<OAuthIcon style={{ width: 14, height: 14 }} />}
            variant="default"
            onClick={() => mutate("generic")}
            loading={isPending}
          >
            {genericName}
          </Button>
        </Grid.Col>
      )}
    </Grid>
  );
};
