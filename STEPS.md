# Projektplan: PHP-Wiki & Backend Migration

Detta dokument beskriver migrationen från en statisk SvelteKit-applikation till en monolitisk PHP-backend (Slim Framework 4) på Loopia med MariaDB och JWT-autentisering.

Fas 1: Backend-infrastruktur & Säkerhet (Skelettet)
Mål: Att sätta upp en säker "Split Deployment" och verifiera databasanslutning.

[X] 1.1 Filstruktur (Split Deployment)

Skapa back-end-core/ (utanför webbrot).

Skapa public_html/api/ (publik webbrot).

[X] 1.2 Miljökonfiguration (.env)

Skapa .env i back-end-core/ med DB-uppgifter, JWT_SECRET och FTP-uppgifter.

[X] 1.3 Composer & Beroenden

Installera slim/slim, slim/psr7, vlucas/phpdotenv, firebase/php-jwt, jimtools/jwt-auth.

[X] 1.4 Databasanslutning

Skapa src/Database.php med PDO-logik.

[X] 1.5 Entry Point & Routing

Skapa index.php i public_html/api/.

Konfigurera .htaccess för URL-rewriting.

[X] 1.6 Verifiering

Testa rutt GET /test-db via Laragon (vvs-proffs.test/test-db).

Fas 2: Autentisering & Användare (Vakten)
Mål: Att implementera JWT-baserad inloggning och rollbaserad åtkomst.

[X] 2.1 Databasschema (Users)

Skapa tabellen users med id, username, password_hash, role (admin/guest).

[X] 2.2 Inloggningslogik

Implementera POST /auth/login som verifierar lösenord och returnerar JWT.

[X] 2.3 JWT Middleware (Vakten)

Aktivera tuupola/slim-jwt-auth för alla rutter utom /auth/login.

[X] 2.4 Initial Admin-användare

Generera och infoga en admin-användare med hashat lösenord i MariaDB.

Fas 3: Wiki API – Läsning (Gäst/Publikt)
Mål: Att leverera wikidata dynamiskt till front-enden via URL-parametrar.

[ ] 3.1 Databasschema (Content)

Skapa tabellerna categories och articles (med LONGTEXT för Markdown).

[ ] 3.2 Meny-endpoint

Skapa GET /wiki/menu som returnerar kategorier och artikeltitlar (JSON).

[ ] 3.3 Artikel-endpoint

Skapa GET /wiki/article/{slug} som hämtar specifikt Markdown-innehåll baserat på URL-parameter.

[ ] 3.4 Metadata

Säkerställ att created_at och updated_at följer med i alla JSON-svar.

Fas 4: Admin API – Skrivning (Endast Admin)
Mål: Att tillåta administratörer att hantera innehåll och användare.

[ ] 4.1 Rollbaserad Middleware

Skapa kontroll som kräver role: admin för specifika rutter.

[ ] 4.2 Innehållshantering (CRUD)

Implementera POST /articles, PUT /articles/{id}, DELETE /articles/{id}.

Implementera motsvarande för categories.

[ ] 4.3 Användaradministration

Implementera POST /users/create och möjligheten att ändra användartyper.

Fas 5: Front-end Transformation (SvelteKit SSG)
Mål: Att ställa om SvelteKit till en statisk sida som konsumerar det nya API:et.

[ ] 5.1 Adapter-byte

Ersätt @sveltejs/adapter-auto med @sveltejs/adapter-static i package.json.

[ ] 5.2 SvelteConfig

Sätt fallback: 'index.html' för att stödja SPA-routing på statisk server.

[ ] 5.3 Prerendering

Konfigurera src/routes/+layout.js med export const prerender = true.

[ ] 5.4 API-Integration

Ersätt lokala JSON-importer med fetch mot din PHP-backend i onMount.

Implementera hantering av Markdown-rendering (t.ex. via bibliotek i Svelte).

[ ] 5.5 Admin UI

Uppdatera inloggningsformulär och redigeringsläge för att prata med de nya PHP-endpoints.

Fas 6: Deployment (Loopia)
Mål: Att rulla ut projektet i produktion.

[ ] 6.1 Production Build

Kör npm run build för front-enden.

[ ] 6.2 FTP Upload

Ladda upp build/ till public_html/.

Ladda upp api/index.php och .htaccess till public_html/api/.

Ladda upp back-end-core/ till en skyddad mapp utanför public_html.

[ ] 6.3 Miljövariabler (Prod)

Skapa en produktions-.env på servern med Loopias specifika MariaDB-host.

Tekniska Krav & Standarder
API Format: Alltid application/json.

Säkerhet: Inga lösenord i klartext. Inga .env-filer i publika mappar.

CORS: Tillåt localhost:5173 under utveckling och din domän i produktion.

Frontend: Svelte 5 Runes för tillståndshantering (t.ex. inloggningsstatus).
