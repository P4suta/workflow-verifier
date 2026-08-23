type request = { url : string; headers : (string * string) list }
type response = { status : int; body : string; effective_url : string }
type get = request -> (response, string) result

let default_sources =
  [
    "https://api.github.com/";
    "https://codeload.github.com/";
    "https://github.com/";
    "https://raw.githubusercontent.com/";
    "https://gitlab.com/";
    "https://circleci.com/";
    "https://dev.azure.com/";
    "https://auth.docker.io/";
    "https://registry-1.docker.io/";
  ]

let is_hex value =
  value <> ""
  && String.for_all
       (function
         | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
         | _ -> false)
       value

let starts_with_any prefixes value =
  List.exists (fun prefix -> Util.starts_with ~prefix value) prefixes

let authority url =
  let prefix = "https://" in
  if not (Util.starts_with ~prefix url) then None
  else
    let start = String.length prefix in
    let stop =
      match String.index_from_opt url start '/' with
      | Some index -> index
      | None -> String.length url
    in
    Some (String.sub url start (stop - start) |> String.lowercase_ascii)

let safe_https_origin url =
  match authority url with
  | None -> false
  | Some host ->
      host <> ""
      && (not (String.contains host '@'))
      && (not (String.contains host '['))
      && host <> "localhost"
      && (not (Util.ends_with ~suffix:".localhost" host))
      && not
           (String.for_all
              (function
                | '0' .. '9' | '.' -> true
                | _ -> false)
              host)

let source_allowed allowed_sources url =
  safe_https_origin url
  && starts_with_any (default_sources @ allowed_sources) url

let fetch ~get ~allowed_sources ?(headers = []) url =
  if not (source_allowed allowed_sources url) then
    Error ("resolver URL is outside the HTTPS source allowlist: " ^ url)
  else
    match get { url; headers } with
    | Error _ as error -> error
    | Ok response ->
        if response.status < 200 || response.status >= 300 then
          Error
            (Printf.sprintf "resolver HTTP status %d for %s" response.status url)
        else if not (source_allowed allowed_sources response.effective_url) then
          Error
            ("resolver redirect escaped the HTTPS source allowlist: "
           ^ response.effective_url)
        else if response.body = "" then
          Error ("resolver returned empty content for " ^ url)
        else Ok response

let url_encode value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (fun character ->
      match character with
      | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '.' | '_' | '~' ->
          Buffer.add_char buffer character
      | value -> Printf.bprintf buffer "%%%02X" (Char.code value))
    value;
  Buffer.contents buffer

let split_nonempty character value =
  String.split_on_char character value
  |> List.filter (fun component -> component <> "")

let split_revision reference =
  match String.rindex_opt reference '@' with
  | None -> Error ("dependency has no revision: " ^ reference)
  | Some index when index = 0 || index = String.length reference - 1 ->
      Error ("dependency has an empty identity or revision: " ^ reference)
  | Some index ->
      Ok
        ( String.sub reference 0 index,
          String.sub reference (index + 1) (String.length reference - index - 1)
        )

let json source =
  match Json.parse source with
  | Ok value -> Ok value
  | Error error ->
      Error
        (Printf.sprintf "resolver JSON byte %d: %s" error.offset error.message)

let member_string name value =
  match Option.bind (Json.member name value) Json.as_string with
  | Some value when value <> "" -> Ok value
  | _ -> Error ("resolver response has no string field " ^ name)

let commit_digest source =
  let value = String.trim source in
  if (String.length value = 40 || String.length value = 64) && is_hex value then
    Ok (String.lowercase_ascii value)
  else Error "resolver returned an invalid commit digest"

let encode_path path =
  path |> String.split_on_char '/'
  |> List.filter (fun value -> value <> "")
  |> List.map url_encode |> String.concat "/"

let github_semantic_source ~get ~allowed_sources ~owner ~repository ~commit
    paths =
  let rec first = function
    | [] -> None
    | path :: rest -> (
        let url =
          Printf.sprintf "https://raw.githubusercontent.com/%s/%s/%s/%s"
            (url_encode owner) (url_encode repository) commit (encode_path path)
        in
        match fetch ~get ~allowed_sources url with
        | Ok response -> Some { Resolver.path; content = response.body }
        | Error _ -> first rest)
  in
  first paths

let resolve_github_repository ~semantic_paths ~get ~allowed_sources ~owner
    ~repository ~path ~revision =
  let api =
    Printf.sprintf "https://api.github.com/repos/%s/%s/commits/%s"
      (url_encode owner) (url_encode repository) (url_encode revision)
  in
  match
    fetch ~get ~allowed_sources
      ~headers:
        [
          ("Accept", "application/vnd.github.sha");
          ("X-GitHub-Api-Version", "2022-11-28");
        ]
      api
  with
  | Error _ as error -> error
  | Ok commit_response -> (
      match commit_digest commit_response.body with
      | Error _ as error -> error
      | Ok commit -> (
          let archive =
            Printf.sprintf "https://codeload.github.com/%s/%s/tar.gz/%s"
              (url_encode owner) (url_encode repository) commit
          in
          match fetch ~get ~allowed_sources archive with
          | Error _ as error -> error
          | Ok archive_response ->
              let suffix = if path = "" then "" else "/" ^ path in
              Ok
                {
                  Resolver.revision = commit;
                  content = archive_response.body;
                  source =
                    Printf.sprintf "https://github.com/%s/%s/tree/%s%s" owner
                      repository commit suffix;
                  semantic_source =
                    github_semantic_source ~get ~allowed_sources ~owner
                      ~repository ~commit semantic_paths;
                }))

let valid_name_component value =
  value <> "" && value <> "." && value <> ".."
  && String.for_all
       (function
         | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' | '.' -> true
         | _ -> false)
       value

let github_action ~get ~allowed_sources reference =
  match split_revision reference with
  | Error _ as error -> error
  | Ok (identity, revision) -> (
      match split_nonempty '/' identity with
      | owner :: repository :: path
        when valid_name_component owner
             && valid_name_component repository
             && List.for_all valid_name_component path ->
          let path = String.concat "/" path in
          let lower_path = String.lowercase_ascii path in
          let semantic_paths =
            if
              Util.ends_with ~suffix:".yml" lower_path
              || Util.ends_with ~suffix:".yaml" lower_path
            then [ path ]
            else
              let prefix = if path = "" then "" else path ^ "/" in
              [ prefix ^ "action.yml"; prefix ^ "action.yaml" ]
          in
          resolve_github_repository ~semantic_paths ~get ~allowed_sources ~owner
            ~repository ~path ~revision
      | _ -> Error ("invalid GitHub dependency reference: " ^ reference))

let direct_https ~get ~allowed_sources reference =
  match fetch ~get ~allowed_sources reference with
  | Error _ as error -> error
  | Ok response ->
      let digest = "sha256:" ^ Sha256.digest_string response.body in
      Ok
        {
          Resolver.revision = digest;
          content = response.body;
          source = response.effective_url;
          semantic_source =
            Some { Resolver.path = reference; content = response.body };
        }

let gitlab_semantic_source ~get ~allowed_sources ~base ~revision path =
  let path =
    if Util.starts_with ~prefix:"/" path then
      String.sub path 1 (String.length path - 1)
    else path
  in
  let lower_path = String.lowercase_ascii path in
  let candidates =
    if path = "" then []
    else if
      Util.ends_with ~suffix:".yml" lower_path
      || Util.ends_with ~suffix:".yaml" lower_path
    then [ path ]
    else [ path ^ "/template.yml"; path ^ ".yml" ]
  in
  let rec first = function
    | [] -> None
    | candidate :: rest -> (
        let url =
          base ^ "/repository/files/" ^ url_encode candidate ^ "/raw?ref="
          ^ url_encode revision
        in
        match fetch ~get ~allowed_sources url with
        | Ok response ->
            Some { Resolver.path = candidate; content = response.body }
        | Error _ -> first rest)
  in
  first candidates

let gitlab_project ~get ~allowed_sources ~host ~project ~requested ~path =
  if
    not
      (valid_name_component host
      && List.length (split_nonempty '/' project) >= 2
      && List.for_all valid_name_component (split_nonempty '/' project))
  then Error "invalid GitLab project locator"
  else
    let base =
      Printf.sprintf "https://%s/api/v4/projects/%s" host (url_encode project)
    in
    let commit_url = base ^ "/repository/commits/" ^ url_encode requested in
    match fetch ~get ~allowed_sources commit_url with
    | Error _ as error -> error
    | Ok response -> (
        match json response.body with
        | Error _ as error -> error
        | Ok value -> (
            match member_string "id" value with
            | Error _ as error -> error
            | Ok revision when String.length revision = 40 && is_hex revision
              -> (
                let archive_url =
                  base ^ "/repository/archive.tar.gz?sha=" ^ revision
                in
                match fetch ~get ~allowed_sources archive_url with
                | Error _ as error -> error
                | Ok archive ->
                    let suffix =
                      if path = "" then ""
                      else if Util.starts_with ~prefix:"/" path then path
                      else "/" ^ path
                    in
                    Ok
                      {
                        Resolver.revision = String.lowercase_ascii revision;
                        content = archive.body;
                        source =
                          Printf.sprintf "https://%s/%s/-/tree/%s%s" host
                            project revision suffix;
                        semantic_source =
                          gitlab_semantic_source ~get ~allowed_sources ~base
                            ~revision path;
                      })
            | Ok _ -> Error "GitLab returned an invalid commit digest"))

let gitlab_component ~get ~allowed_sources reference =
  match split_revision reference with
  | Error _ as error -> error
  | Ok (identity, version) -> (
      match split_nonempty '/' identity with
      | host :: rest when List.length rest >= 2 -> (
          match List.rev rest with
          | component :: reversed_project ->
              let project = List.rev reversed_project |> String.concat "/" in
              if not (valid_name_component component) then
                Error ("invalid GitLab component reference: " ^ reference)
              else
                gitlab_project ~get ~allowed_sources ~host ~project
                  ~requested:version ~path:("templates/" ^ component)
          | [] -> Error ("invalid GitLab component reference: " ^ reference))
      | _ -> Error ("invalid GitLab component reference: " ^ reference))

let gitlab_repository_file ~get ~allowed_sources ~repository ~revision ~path =
  match revision with
  | None -> Error "GitLab project include has no immutable revision"
  | Some requested ->
      let components = split_nonempty '/' repository in
      let host, project =
        match components with
        | host :: rest when String.contains host '.' ->
            (host, String.concat "/" rest)
        | _ -> ("gitlab.com", repository)
      in
      gitlab_project ~get ~allowed_sources ~host ~project ~requested ~path

let exact_semver value =
  let core =
    match String.index_opt value '-' with
    | Some index -> String.sub value 0 index
    | None -> (
        match String.index_opt value '+' with
        | Some index -> String.sub value 0 index
        | None -> value)
  in
  match String.split_on_char '.' core with
  | [ major; minor; patch ] ->
      List.for_all
        (fun part ->
          part <> ""
          && String.for_all
               (function
                 | '0' .. '9' -> true
                 | _ -> false)
               part)
        [ major; minor; patch ]
  | _ -> false

let circleci_orb ~get ~allowed_sources reference =
  if Util.starts_with ~prefix:"https://" reference then
    direct_https ~get ~allowed_sources reference
  else
    match split_revision reference with
    | Error _ as error -> error
    | Ok (identity, version) -> (
        if
          List.length (split_nonempty '/' identity) <> 2
          || not (exact_semver version)
        then
          Error
            ("CircleCI orb must use an exact production SemVer: " ^ reference)
        else
          let version_url =
            "https://circleci.com/api/v3/orb/versions?filter%5Bref%5D="
            ^ url_encode reference
          in
          match fetch ~get ~allowed_sources version_url with
          | Error _ as error -> error
          | Ok response -> (
              match json response.body with
              | Error _ as error -> error
              | Ok root -> (
                  match Option.bind (Json.member "data" root) Json.as_array with
                  | Some [ item ] -> (
                      match
                        ( member_string "id" item,
                          Option.bind
                            (Option.bind
                               (Json.member "attributes" item)
                               (Json.member "version"))
                            Json.as_string )
                      with
                      | Ok id, Some actual when actual = version -> (
                          let source_url =
                            "https://circleci.com/api/v3/orb/versions/"
                            ^ url_encode id ^ "/source"
                          in
                          match fetch ~get ~allowed_sources source_url with
                          | Error _ as error -> error
                          | Ok source ->
                              Ok
                                {
                                  Resolver.revision = version;
                                  content = source.body;
                                  source =
                                    "https://circleci.com/developer/orbs/orb/"
                                    ^ identity ^ "/" ^ version;
                                  semantic_source =
                                    Some
                                      {
                                        Resolver.path = ".circleci/config.yml";
                                        content = source.body;
                                      };
                                })
                      | Ok _, Some _ ->
                          Error "CircleCI returned a different orb version"
                      | (Error _ as error), _ -> error
                      | _, None -> Error "CircleCI orb response has no version")
                  | _ ->
                      Error "CircleCI orb response is missing one exact version"
                  )))

let azure_task ~get ~allowed_sources reference =
  match split_revision reference with
  | Error _ as error -> error
  | Ok (name, major)
    when valid_name_component name && major <> ""
         && String.for_all
              (function
                | '0' .. '9' -> true
                | _ -> false)
              major -> (
      let task_path = "Tasks/" ^ name ^ "V" ^ major in
      match
        resolve_github_repository ~get ~allowed_sources ~owner:"microsoft"
          ~repository:"azure-pipelines-tasks" ~path:"" ~revision:"main"
          ~semantic_paths:[ task_path ^ "/task.json" ]
      with
      | Error _ as error -> error
      | Ok fetched ->
          Ok { fetched with source = fetched.source ^ "/" ^ task_path })
  | Ok _ -> Error ("invalid Azure task reference: " ^ reference)

let azure_repository_parts identity =
  match split_nonempty '/' identity with
  | [ "https:"; "dev.azure.com"; organization; project; "_git"; repository ] ->
      Some (organization, project, repository)
  | [ organization; project; repository ] ->
      Some (organization, project, repository)
  | _ -> None

let azure_repository ~get ~allowed_sources reference =
  match split_revision reference with
  | Error _ as error -> error
  | Ok (identity, requested) -> (
      match azure_repository_parts identity with
      | None -> Error ("invalid Azure repository reference: " ^ reference)
      | Some (organization, project, repository) -> (
          let api_base =
            Printf.sprintf
              "https://dev.azure.com/%s/%s/_apis/git/repositories/%s"
              (url_encode organization) (url_encode project)
              (url_encode repository)
          in
          let commits =
            api_base ^ "/commits?searchCriteria.itemVersion.version="
            ^ url_encode requested ^ "&searchCriteria.%24top=1&api-version=7.1"
          in
          match fetch ~get ~allowed_sources commits with
          | Error _ as error -> error
          | Ok response -> (
              match json response.body with
              | Error _ as error -> error
              | Ok root -> (
                  match
                    Option.bind (Json.member "value" root) Json.as_array
                  with
                  | Some (commit :: _) -> (
                      match member_string "commitId" commit with
                      | Error _ as error -> error
                      | Ok revision
                        when String.length revision = 40 && is_hex revision -> (
                          let archive =
                            api_base
                            ^ "/items?scopePath=%2F&recursionLevel=Full&download=true&%24format=zip&versionDescriptor.version="
                            ^ revision ^ "&api-version=7.1"
                          in
                          match fetch ~get ~allowed_sources archive with
                          | Error _ as error -> error
                          | Ok contents ->
                              Ok
                                {
                                  Resolver.revision =
                                    String.lowercase_ascii revision;
                                  content = contents.body;
                                  source =
                                    Printf.sprintf
                                      "https://dev.azure.com/%s/%s/_git/%s?version=GC%s"
                                      organization project repository revision;
                                  semantic_source = None;
                                })
                      | Ok _ -> Error "Azure returned an invalid commit digest")
                  | _ -> Error "Azure repository response contains no commit")))
      )

let azure_semantic_source ~get ~allowed_sources ~repository ~revision path =
  match azure_repository_parts repository with
  | None -> None
  | Some (organization, project, name) -> (
      let path =
        if Util.starts_with ~prefix:"/" path then path else "/" ^ path
      in
      let api_base =
        Printf.sprintf "https://dev.azure.com/%s/%s/_apis/git/repositories/%s"
          (url_encode organization) (url_encode project) (url_encode name)
      in
      let url =
        api_base ^ "/items?path=" ^ url_encode path
        ^ "&includeContent=true&versionDescriptor.versionType=commit&versionDescriptor.version="
        ^ url_encode revision ^ "&api-version=7.1"
      in
      match fetch ~get ~allowed_sources url with
      | Ok response ->
          Some
            {
              Resolver.path = String.sub path 1 (String.length path - 1);
              content = response.body;
            }
      | Error _ -> None)

let github_repository_locator ~get ~allowed_sources ~repository ~revision ~path
    =
  match (split_nonempty '/' repository, revision) with
  | [ owner; name ], Some revision
    when valid_name_component owner && valid_name_component name ->
      resolve_github_repository ~get ~allowed_sources ~owner ~repository:name
        ~path ~revision
        ~semantic_paths:(if path = "" then [] else [ path ])
  | _, None -> Error "repository resource has no immutable revision"
  | _ -> Error ("invalid GitHub repository locator: " ^ repository)

let azure_repository_locator ~get ~allowed_sources ~repository ~revision ~path
    ~repository_type =
  let repository_type = Option.map String.lowercase_ascii repository_type in
  match repository_type with
  | Some "github" ->
      github_repository_locator ~get ~allowed_sources ~repository ~revision
        ~path
  | None | Some "git" | Some "azurereposgit" -> (
      match revision with
      | None -> Error "Azure repository resource has no immutable revision"
      | Some revision -> (
          match
            azure_repository ~get ~allowed_sources (repository ^ "@" ^ revision)
          with
          | Error _ as error -> error
          | Ok fetched when path = "" -> Ok fetched
          | Ok fetched ->
              Ok
                {
                  fetched with
                  source = fetched.source ^ "#path=" ^ url_encode path;
                  semantic_source =
                    azure_semantic_source ~get ~allowed_sources ~repository
                      ~revision:fetched.revision path;
                }))
  | Some kind -> Error ("unsupported Azure repository type " ^ kind)

let strip_prefix prefix value =
  if Util.starts_with ~prefix value then
    String.sub value (String.length prefix)
      (String.length value - String.length prefix)
  else value

let parse_image reference =
  let reference = strip_prefix "docker://" reference in
  match String.index_opt reference '@' with
  | Some index ->
      let name = String.sub reference 0 index
      and digest =
        String.sub reference (index + 1) (String.length reference - index - 1)
      in
      if
        valid_name_component (Filename.basename name)
        && Util.starts_with ~prefix:"sha256:" digest
        && String.length digest = 71
        && is_hex (String.sub digest 7 64)
      then Ok (`Pinned (name, String.lowercase_ascii digest))
      else Error ("invalid OCI image digest: " ^ reference)
  | None -> (
      let slash = String.rindex_opt reference '/' in
      let colon = String.rindex_opt reference ':' in
      let name, tag =
        match colon with
        | Some index when Option.fold ~none:true ~some:(( < ) index) slash ->
            ( String.sub reference 0 index,
              String.sub reference (index + 1)
                (String.length reference - index - 1) )
        | _ -> (reference, "latest")
      in
      let components = split_nonempty '/' name in
      match components with
      | [] -> Error ("invalid OCI image: " ^ reference)
      | _ when tag = "" -> Error ("invalid OCI image: " ^ reference)
      | first :: remaining ->
          let explicit_registry =
            String.contains first '.' || String.contains first ':'
          in
          if explicit_registry then
            Ok (`Tagged (first, String.concat "/" remaining, tag))
          else
            let repository =
              if List.length components = 1 then "library/" ^ name else name
            in
            Ok (`Tagged ("registry-1.docker.io", repository, tag)))

let bearer_token source =
  match json source with
  | Error _ as error -> error
  | Ok value -> (
      match member_string "token" value with
      | Ok _ as result -> result
      | Error _ -> member_string "access_token" value)

let container_image ~get ~allowed_sources reference =
  match parse_image reference with
  | Error _ as error -> error
  | Ok (`Pinned (name, digest)) ->
      Ok
        {
          Resolver.revision = digest;
          content = name ^ "@" ^ digest;
          source = "oci://" ^ name ^ "@" ^ digest;
          semantic_source = None;
        }
  | Ok (`Tagged (registry, repository, tag)) -> (
      let manifest_url =
        Printf.sprintf "https://%s/v2/%s/manifests/%s" registry repository
          (url_encode tag)
      and accept =
        ( "Accept",
          "application/vnd.oci.image.index.v1+json, \
           application/vnd.oci.image.manifest.v1+json, \
           application/vnd.docker.distribution.manifest.list.v2+json, \
           application/vnd.docker.distribution.manifest.v2+json" )
      in
      let headers =
        if registry <> "registry-1.docker.io" then Ok [ accept ]
        else
          let token_url =
            "https://auth.docker.io/token?service=registry.docker.io&scope="
            ^ url_encode ("repository:" ^ repository ^ ":pull")
          in
          match fetch ~get ~allowed_sources token_url with
          | Error _ as error -> error
          | Ok response -> (
              match bearer_token response.body with
              | Error _ as error -> error
              | Ok token -> Ok [ accept; ("Authorization", "Bearer " ^ token) ])
      in
      match headers with
      | Error _ as error -> error
      | Ok headers -> (
          match fetch ~get ~allowed_sources ~headers manifest_url with
          | Error _ as error -> error
          | Ok manifest ->
              let digest = "sha256:" ^ Sha256.digest_string manifest.body in
              Ok
                {
                  Resolver.revision = digest;
                  content = manifest.body;
                  source =
                    Printf.sprintf "oci://%s/%s@%s" registry repository digest;
                  semantic_source = None;
                }))

let resolve ~get ~allowed_sources (dependency : Frontend_intf.dependency) =
  if dependency.kind = Frontend_intf.Container_image then
    container_image ~get ~allowed_sources dependency.reference
  else
    match (dependency.provider, dependency.locator, dependency.kind) with
    | ( Gitlab,
        Repository_file { repository; revision; path; repository_type = _ },
        _ ) ->
        gitlab_repository_file ~get ~allowed_sources ~repository ~revision ~path
    | Azure, Repository_file { repository; revision; path; repository_type }, _
      ->
        azure_repository_locator ~get ~allowed_sources ~repository ~revision
          ~path ~repository_type
    | Azure, Repository_source { repository; revision; repository_type }, _ ->
        azure_repository_locator ~get ~allowed_sources ~repository ~revision
          ~path:"" ~repository_type
    | Ir.Github, _, (Action | Repository | Template) ->
        github_action ~get ~allowed_sources dependency.reference
    | Gitlab, _, Component ->
        gitlab_component ~get ~allowed_sources dependency.reference
    | Azure, _, Task -> azure_task ~get ~allowed_sources dependency.reference
    | Azure, _, Repository ->
        azure_repository ~get ~allowed_sources dependency.reference
    | Circleci, _, Orb ->
        circleci_orb ~get ~allowed_sources dependency.reference
    | _, _, _ when Util.starts_with ~prefix:"https://" dependency.reference ->
        direct_https ~get ~allowed_sources dependency.reference
    | _, _, _ ->
        Error
          (Printf.sprintf "no safe resolver for %s dependency %s"
             (Frontend_intf.dependency_kind_name dependency.kind)
             dependency.reference)

let make ~get ~allowed_sources =
  { Resolver.fetch = resolve ~get ~allowed_sources }
