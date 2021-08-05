import {
  ApolloClient,
  createHttpLink,
  InMemoryCache,
  fromPromise,
  ApolloLink,
  NormalizedCacheObject,
  Reference,
} from "@apollo/client";
import { onError } from "@apollo/client/link/error";
import { setContext } from "@apollo/client/link/context";
import jwtDecode from "jwt-decode";
import { TypedTypePolicies } from "./apollo-helpers";
import { REFRESH_TOKEN } from "./mutations";
import { RefreshTokenMutation, RefreshTokenMutationVariables } from "./types";
import { storage } from "../core/storage";

type JWTToken = {
  iat: number;
  iss: string;
  owner: string;
  exp: number;
  token: string;
  email: string;
  type: string;
  user_id: string;
  is_staff: boolean;
};

let client: ApolloClient<NormalizedCacheObject> | undefined;

const refreshToken = async (
  callback: (token: string) => void
): Promise<void> => {
  try {
    const { data } = await client!.mutate<
      RefreshTokenMutation,
      RefreshTokenMutationVariables
    >({
      mutation: REFRESH_TOKEN,
    });
    if (data?.tokenRefresh?.token) {
      storage.setToken(data.tokenRefresh.token);
      callback(data?.tokenRefresh?.token);
    }
  } catch (error) {
    storage.setToken("");
    client!.resetStore();
  }
};

const autoRefreshFetch = async (
  input: RequestInfo,
  init: RequestInit
): Promise<Response> => {
  const initialRequest = fetch(input, init);
  const token = storage.getToken();

  if (JSON.parse(`${init.body}`).operationName === "refreshToken") {
    return await initialRequest;
  }

  if (token) {
    // auto refresh token before 60 sec until it expires
    const expirationTime = jwtDecode<JWTToken>(token).exp * 1000 - 60000;
    if (Date.now() >= expirationTime) {
      await refreshToken((token: string) => {
        init.headers = {
          ...init.headers,
          authorization: `JWT ${token}`,
        };
      });
    }
  }

  return await initialRequest;
};

const authLink = setContext((_, { headers }) => {
  const token = storage.getToken();

  return {
    headers: {
      ...headers,
      authorization: token ? `JWT ${token}` : "",
    },
  };
});

const errorLink = onError(
  ({ graphQLErrors, networkError, operation, forward }) => {
    if (graphQLErrors) {
      const isUnAuthenticated = graphQLErrors.some(
        error => error.extensions && error.extensions.code === "UNAUTHENTICATED"
      );

      if (isUnAuthenticated) {
        return fromPromise(
          refreshToken((token: string) => {
            const oldHeaders = operation.getContext().headers;
            operation.setContext({
              headers: {
                ...oldHeaders,
                authorization: `JWT ${token}`,
              },
            });
          })
        )
          .filter(Boolean)
          .flatMap(() => forward(operation));
      }

      graphQLErrors.forEach(({ message, locations, path }) => {
        console.log(
          `[GraphQL error]: Message: ${message}, Location: ${locations}, Path: ${path}`
        );
      });
    }

    if (networkError) {
      console.log(`[Network error]: ${networkError}`);
    }

    return;
  }
);

const createLink = (uri: string): ApolloLink => {
  const httpLink = createHttpLink({
    fetch: autoRefreshFetch,
    uri,
    credentials: "include",
  });

  return ApolloLink.from([errorLink, authLink, httpLink]);
};

const typePolicies: TypedTypePolicies = {
  Query: {
    fields: {
      authenticated: {
        read(_, { readField, toReference }): boolean {
          return !!readField(
            "id",
            toReference({
              __typename: "User",
            })
          );
        },
      },
      me: {
        read(_, { toReference, canRead }): Reference | undefined | null {
          const ref = toReference({
            __typename: "User",
          });

          return canRead(ref) ? ref : null;
        },
      },
      token: {
        read(): string | null {
          return storage.getToken();
        },
      },
    },
  },
  User: {
    /**
     * IMPORTANT
     * This works as long as we have 1 User cache object which is the current logged in User.
     * If the client should ever fetch additional Users, this should be removed
     * and the login methods (token create or verify) should be responsible for writing USER query cache manually.
     */
    keyFields: [],
    fields: {
      addresses: {
        merge: false,
      },
    },
  },
};

export const cache = new InMemoryCache({
  typePolicies,
});

export const createApolloClient = (
  apiUrl: string
): ApolloClient<NormalizedCacheObject> => {
  client = new ApolloClient({
    cache,
    link: createLink(apiUrl),
  });

  return client;
};
