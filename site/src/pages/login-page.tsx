import {
  Button,
  Paper,
  PasswordInput,
  TextInput,
  Title,
  Text,
  Divider,
  Grid,
} from "@mantine/core";
import { useForm, zodResolver } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { z } from "zod";
import { useUserContext } from "../context/user-context";
import { Navigate } from "react-router";
import { Layout } from "../components/layouts/layout";
import { GoogleIcon } from "../icons/google";
import { GithubIcon } from "../icons/github";
import { OAuthIcon } from "../icons/oauth";
import { TailscaleIcon } from "../icons/tailscale";
import { isQueryValid } from "../utils/utils";

export const LoginPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri") ?? "";

  const { isLoggedIn, configuredProviders, title, genericName } = useUserContext();

  const oauthProviders = configuredProviders.filter(
    (value) => value !== "username",
  );

  if (isLoggedIn) {
    return <Navigate to="/logout" />;
  }

  const schema = z.object({
    username: z.string(),
    password: z.string(),
  });

  type FormValues = z.infer<typeof schema>;

  const form = useForm({
    mode: "uncontrolled",
    initialValues: {
      username: "",
      password: "",
    },
    validate: zodResolver(schema),
  });

  const loginMutation = useMutation({
    mutationFn: (login: FormValues) => {
      return axios.post("/api/login", login);
    },
    onError: () => {
      notifications.show({
        title: "Failed to login",
        message: "Check your username and password",
        color: "red",
      });
    },
    onSuccess: () => {
      notifications.show({
        title: "Logged in",
        message: "Welcome back!",
        color: "green",
      });
      setTimeout(() => {
        if (!isQueryValid(redirectUri)) {
          window.location.replace("/");
        } else {
          window.location.replace(`/continue?redirect_uri=${redirectUri}`);
        }
      }, 500);
    },
  });

  const loginOAuthMutation = useMutation({
    mutationFn: (provider: string) => {
      return axios.get(
        `/api/oauth/url/${provider}?redirect_uri=${redirectUri}`,
      );
    },
    onError: () => {
      notifications.show({
        title: "Internal error",
        message: "Failed to get OAuth URL",
        color: "red",
      });
    },
    onSuccess: (data) => {
      notifications.show({
        title: "Redirecting",
        message: "Redirecting to your OAuth provider",
        color: "blue",
      });
      setTimeout(() => {
        window.location.href = data.data.url;
      }, 500);
    },
  });

  const handleSubmit = (values: FormValues) => {
    loginMutation.mutate(values);
  };

  return (
    <Layout>
      <Title ta="center">{title}</Title>
      <Paper shadow="md" p="xl" mt={30} radius="md" withBorder>
        {oauthProviders.length > 0 && (
          <>
            <Text size="lg" fw={500} ta="center">
              Welcome back, login with
            </Text>
            <Grid mb="md" mt="md" align="center" justify="center">
              {oauthProviders.includes("google") && (
                <Grid.Col span="content">
                  <Button
                    radius="xl"
                    leftSection={
                      <GoogleIcon style={{ width: 14, height: 14 }} />
                    }
                    variant="default"
                    onClick={() => loginOAuthMutation.mutate("google")}
                    loading={loginOAuthMutation.isLoading}
                  >
                    Google
                  </Button>
                </Grid.Col>
              )}
              {oauthProviders.includes("github") && (
                <Grid.Col span="content">
                  <Button
                    radius="xl"
                    leftSection={
                      <GithubIcon style={{ width: 14, height: 14 }} />
                    }
                    variant="default"
                    onClick={() => loginOAuthMutation.mutate("github")}
                    loading={loginOAuthMutation.isLoading}
                  >
                    Github
                  </Button>
                </Grid.Col>
              )}
              {oauthProviders.includes("tailscale") && (
                <Grid.Col span="content">
                  <Button
                    radius="xl"
                    leftSection={
                      <TailscaleIcon style={{ width: 14, height: 14 }} />
                    }
                    variant="default"
                    onClick={() => loginOAuthMutation.mutate("tailscale")}
                    loading={loginOAuthMutation.isLoading}
                  >
                    Tailscale
                  </Button>
                </Grid.Col>
              )}
              {oauthProviders.includes("generic") && (
                <Grid.Col span="content">
                  <Button
                    radius="xl"
                    leftSection={
                      <OAuthIcon style={{ width: 14, height: 14 }} />
                    }
                    variant="default"
                    onClick={() => loginOAuthMutation.mutate("generic")}
                    loading={loginOAuthMutation.isLoading}
                  >
                    {genericName}
                  </Button>
                </Grid.Col>
              )}
            </Grid>
            {configuredProviders.includes("username") && (
              <Divider
                label="Or continue with password"
                labelPosition="center"
                my="lg"
              />
            )}
          </>
        )}
        {configuredProviders.includes("username") && (
          <form onSubmit={form.onSubmit(handleSubmit)}>
            <TextInput
              label="Username"
              placeholder="user@example.com"
              required
              disabled={loginMutation.isLoading}
              key={form.key("username")}
              {...form.getInputProps("username")}
            />
            <PasswordInput
              label="Password"
              placeholder="password"
              required
              mt="md"
              disabled={loginMutation.isLoading}
              key={form.key("password")}
              {...form.getInputProps("password")}
            />
            <Button
              fullWidth
              mt="xl"
              type="submit"
              loading={loginMutation.isLoading}
            >
              Login
            </Button>
          </form>
        )}
      </Paper>
    </Layout>
  );
};
