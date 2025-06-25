import styled from "styled-components";
import { Button } from "@mui/material";

// #FFFFFF - alb
// #C3C3C3 - light gray
// #7F7F7F - dark gray

export const Container = styled.div`
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    background-color: #C3C3C3;
    color: white;
    font-family: "Arial", sans-serif;
`;

export const Content = styled.div`
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 95%;
    margin: 0 auto;
    gap: 0.5rem;
    height: 100%;
    overflow: hidden;
`;

export const UpperBox = styled.div`
    width: 100%;
    background-color: #fff;
    border-radius: 8px;
    color: black;
`;

export const LowerBox = styled.div`
    display: flex;
    flex: 1;
    overflow: hidden;
    height: 100%;
    gap: 0.5rem;
    width: 100%;

    @media (max-width: 900px) {
        flex-direction: column;
    }
`;

export const LeftSection = styled.div`
    flex: 1;
    max-width: 900px;
    height: calc(100vh - 625px);
    background-color: #fff;
    padding: 1rem;
    border-radius: 8px;
    color: black;
    overflow-y: auto;
`;

export const RightSection = styled.div`
    flex: 1;
    max-width: 900px;
    height: calc(100vh - 625px);
    background-color: #fff;
    padding: 1rem;
    border-radius: 8px;
    color: black;
    overflow-y: auto;
`;

export const PrimaryButton = styled(Button)`
  && {
    background-color: #F46601;
    border: 2px solid #F46601;
    color: white;
    border-radius: 999px;
    padding: 10px 25px;
    font-weight: bold;
    text-transform: none;

    &:hover {
      background-color: #FF7A00;
    }
  }
`;

export const SecondaryButton = styled(PrimaryButton)`
  && {
    background-color: #100800;
    border: 2px solid #F46601;
    margin-left: 0.5rem;

    &:hover {
      background-color: #222;
    }
  }
`;
