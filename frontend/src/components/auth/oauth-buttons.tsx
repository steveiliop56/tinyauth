import { Grid, Button } from "@mantine/core";
import { GithubIcon } from "../../icons/github";
import { GoogleIcon } from "../../icons/google";
import { OAuthIcon } from "../../icons/oauth";

interface OAuthButtonsProps {
  oauthProviders: string[];
  isLoading: boolean;
  mutate: (provider: string) => void;
  genericName: string;
}

export const OAuthButtons = (props: OAuthButtonsProps) => {
  const { oauthProviders, isLoading, genericName, mutate } = props;
  return (
    <Grid mb="md" mt="md" align="center" justify="center">
      {oauthProviders.includes("google") && (
        <Grid.Col span="content">
          <Button
            radius="xl"
            leftSection={<GoogleIcon style={{ width: 14, height: 14 }} />}
            variant="default"
            onClick={() => mutate("google")}
            loading={isLoading}
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
            loading={isLoading}
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
            loading={isLoading}
          >
            {genericName}
          </Button>
        </Grid.Col>
      )}
    </Grid>
  );
};
